#!/usr/bin/env node
"use strict";

/*
 * Fetches and verifies the tenantguard binary for one platform/arch from the
 * pinned v0.1.1 GitHub release, then extracts it into the calling package's
 * bin/ directory.
 *
 * Runs ONLY as a "prepack" lifecycle script -- i.e. only on the machine that
 * runs `npm pack` / `npm publish` for a platform package, right before the
 * tarball is assembled. It never runs at end-user `npm install` time; the
 * binary that ships to end users is already a plain file in the published
 * tarball, covered by npm's own integrity/shasum checks like any other
 * dependency. This keeps the network fetch out of the end-user install path
 * entirely, which is the whole point of not using a postinstall script here.
 *
 * The download itself is verified against the release's own checksums.txt
 * (SHA-256) before anything is extracted. A checksum mismatch, a missing
 * checksum entry, a failed download, or a missing binary inside the archive
 * all fail loudly (non-zero exit) -- this script never extracts or ships an
 * unverified binary.
 *
 * Usage: node fetch-binary.js <goos> <goarch> <archive-ext> <binary-name>
 *   e.g. node fetch-binary.js darwin arm64 tar.gz tenantguard
 *        node fetch-binary.js windows amd64 zip tenantguard.exe
 *
 * Must be invoked with cwd set to the platform package's root (this is how
 * npm always runs lifecycle scripts), since the extracted binary is written
 * to ./bin/<binary-name> relative to the current working directory.
 */

const https = require("https");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const RELEASE_TAG = "v0.1.1";
const RELEASE_BASE = `https://github.com/RudrenduPaul/TenantGuard/releases/download/${RELEASE_TAG}`;
const MAX_REDIRECTS = 5;

function fail(message) {
  console.error(`fetch-binary: ${message}`);
  process.exit(1);
}

const [, , goos, goarch, ext, binaryName] = process.argv;
if (!goos || !goarch || !ext || !binaryName) {
  fail(
    "usage: node fetch-binary.js <goos> <goarch> <archive-ext> <binary-name>\n" +
      "  e.g. node fetch-binary.js darwin arm64 tar.gz tenantguard"
  );
}
if (ext !== "tar.gz" && ext !== "zip") {
  fail(`unsupported archive extension "${ext}" (expected "tar.gz" or "zip")`);
}

const archiveName = `tenantguard_${goos}_${goarch}.${ext}`;
const archiveUrl = `${RELEASE_BASE}/${archiveName}`;
const checksumsUrl = `${RELEASE_BASE}/checksums.txt`;

function get(url, redirectsLeft) {
  if (redirectsLeft === undefined) redirectsLeft = MAX_REDIRECTS;
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { "User-Agent": "tenantguard-npm-fetch-binary" } }, (res) => {
        const status = res.statusCode || 0;
        if ([301, 302, 303, 307, 308].includes(status) && res.headers.location) {
          res.resume();
          if (redirectsLeft <= 0) return reject(new Error(`too many redirects fetching ${url}`));
          return resolve(get(res.headers.location, redirectsLeft - 1));
        }
        if (status !== 200) {
          res.resume();
          return reject(new Error(`GET ${url} failed: HTTP ${status}`));
        }
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => resolve(Buffer.concat(chunks)));
        res.on("error", reject);
      })
      .on("error", reject);
  });
}

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

// checksums.txt lines look like: "<64 hex chars>  <filename>" (goreleaser's
// default sha256sum-compatible format; tolerate an optional leading "*").
function parseChecksums(text) {
  const map = new Map();
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    const match = line.match(/^([0-9a-fA-F]{64})\s+\*?(.+)$/);
    if (!match) continue;
    map.set(match[2].trim(), match[1].toLowerCase());
  }
  return map;
}

// --- minimal ustar/tar reader: extract a single named entry from a
// decompressed tar stream. Only what's needed to pull one file out of a
// goreleaser-produced .tar.gz -- not a general-purpose tar implementation.
function extractFromTarGz(tarGzBuf, targetBasename) {
  const tarBuf = zlib.gunzipSync(tarGzBuf);
  let offset = 0;
  while (offset + 512 <= tarBuf.length) {
    const header = tarBuf.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break; // end-of-archive marker block

    const rawName = header.subarray(0, 100).toString("utf8").replace(/\0.*$/, "");
    const sizeField = header.subarray(124, 136).toString("utf8").replace(/\0.*$/, "").trim();
    const size = sizeField ? parseInt(sizeField, 8) : 0;
    const dataStart = offset + 512;

    if (path.basename(rawName) === targetBasename) {
      return tarBuf.subarray(dataStart, dataStart + size);
    }

    const blocks = Math.ceil(size / 512);
    offset = dataStart + blocks * 512;
  }
  return null;
}

// --- minimal zip reader: locate the central directory, find the named
// entry, then decompress its data (stored or deflate) from the local file
// header. Only what's needed to pull one file out of a goreleaser-produced
// .zip -- not a general-purpose zip implementation.
function extractFromZip(zipBuf, targetBasename) {
  const EOCD_SIG = 0x06054b50;
  const CENTRAL_DIR_SIG = 0x02014b50;

  let eocdOffset = -1;
  for (let i = zipBuf.length - 22; i >= 0; i--) {
    if (zipBuf.readUInt32LE(i) === EOCD_SIG) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset === -1) throw new Error("zip: end-of-central-directory record not found");

  const entryCount = zipBuf.readUInt16LE(eocdOffset + 10);
  let offset = zipBuf.readUInt32LE(eocdOffset + 16);

  for (let i = 0; i < entryCount; i++) {
    const sig = zipBuf.readUInt32LE(offset);
    if (sig !== CENTRAL_DIR_SIG) throw new Error("zip: malformed central directory entry");

    const method = zipBuf.readUInt16LE(offset + 10);
    const compressedSize = zipBuf.readUInt32LE(offset + 20);
    const nameLen = zipBuf.readUInt16LE(offset + 28);
    const extraLen = zipBuf.readUInt16LE(offset + 30);
    const commentLen = zipBuf.readUInt16LE(offset + 32);
    const localHeaderOffset = zipBuf.readUInt32LE(offset + 42);
    const name = zipBuf.subarray(offset + 46, offset + 46 + nameLen).toString("utf8");

    if (path.basename(name) === targetBasename) {
      const lfhNameLen = zipBuf.readUInt16LE(localHeaderOffset + 26);
      const lfhExtraLen = zipBuf.readUInt16LE(localHeaderOffset + 28);
      const dataStart = localHeaderOffset + 30 + lfhNameLen + lfhExtraLen;
      const compressed = zipBuf.subarray(dataStart, dataStart + compressedSize);

      if (method === 0) return compressed; // stored, no compression
      if (method === 8) return zlib.inflateRawSync(compressed); // deflate
      throw new Error(`zip: unsupported compression method ${method} for ${name}`);
    }

    offset += 46 + nameLen + extraLen + commentLen;
  }
  return null;
}

async function main() {
  console.log(`fetch-binary: downloading ${archiveUrl}`);
  const [archiveBuf, checksumsBuf] = await Promise.all([get(archiveUrl), get(checksumsUrl)]);

  const checksums = parseChecksums(checksumsBuf.toString("utf8"));
  const expected = checksums.get(archiveName);
  if (!expected) {
    fail(`no checksum entry for "${archiveName}" found in the release's checksums.txt -- refusing to proceed`);
    return;
  }

  const actual = sha256Hex(archiveBuf);
  if (actual !== expected) {
    fail(
      `checksum mismatch for ${archiveName}: expected ${expected}, got ${actual}. ` +
        `Refusing to extract an unverified binary.`
    );
    return;
  }
  console.log(`fetch-binary: checksum verified for ${archiveName} (sha256:${actual})`);

  let binaryData;
  try {
    binaryData = ext === "zip" ? extractFromZip(archiveBuf, binaryName) : extractFromTarGz(archiveBuf, binaryName);
  } catch (err) {
    fail(`failed to extract ${binaryName} from ${archiveName}: ${err.message}`);
    return;
  }

  if (!binaryData || binaryData.length === 0) {
    fail(`could not find a non-empty "${binaryName}" entry inside ${archiveName}`);
    return;
  }

  const outDir = path.join(process.cwd(), "bin");
  const outPath = path.join(outDir, binaryName);
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(outPath, binaryData);
  if (process.platform !== "win32") {
    fs.chmodSync(outPath, 0o755);
  }

  console.log(`fetch-binary: wrote verified binary to ${outPath} (${binaryData.length} bytes)`);
}

main().catch((err) => fail(err && err.message ? err.message : String(err)));
