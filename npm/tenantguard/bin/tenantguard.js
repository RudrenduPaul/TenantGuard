#!/usr/bin/env node
"use strict";

// Thin shim: resolve the prebuilt binary for the current platform/arch from
// this package's optionalDependencies (npm's own os/cpu gating means only
// the one matching package is ever installed), then exec it directly. No
// network fetch happens here -- the binary already arrived as a normal npm
// dependency, covered by npm's own integrity/shasum checks on install.

const { spawnSync } = require("child_process");

// Keys are `${process.platform}-${process.arch}`. Values are the
// optionalDependency package names declared in package.json -- keep these
// two lists in sync. Unscoped (tenantguard-<platform>-<arch>), matching the
// names actually published to the npm registry, not the @tenantguard/*
// scope this file originally used.
const PLATFORM_PACKAGES = {
  "darwin-x64": "tenantguard-darwin-x64",
  "darwin-arm64": "tenantguard-darwin-arm64",
  "linux-x64": "tenantguard-linux-x64",
  "linux-arm64": "tenantguard-linux-arm64",
  "win32-x64": "tenantguard-win32-x64",
  "win32-arm64": "tenantguard-win32-arm64",
};

function fail(message) {
  console.error(message);
  process.exit(1);
}

const platformKey = `${process.platform}-${process.arch}`;
const pkgName = PLATFORM_PACKAGES[platformKey];
const supportedList = Object.keys(PLATFORM_PACKAGES).join(", ");

if (!pkgName) {
  fail(
    `tenantguard: no prebuilt binary available for ${process.platform}/${process.arch}.\n` +
      `Supported platforms: ${supportedList}.`
  );
}

const binaryName = process.platform === "win32" ? "tenantguard.exe" : "tenantguard";

let binPath;
try {
  binPath = require.resolve(`${pkgName}/bin/${binaryName}`);
} catch (err) {
  fail(
    `tenantguard: the platform package "${pkgName}" for ${process.platform}/${process.arch} is not installed.\n` +
      `This usually means npm skipped installing it as an optional dependency\n` +
      `(for example, because it was installed with --omit=optional, or npm\n` +
      `couldn't resolve it for this platform).\n` +
      `Try: npm install tenantguard --include=optional\n` +
      `Supported platforms: ${supportedList}.`
  );
}

const result = spawnSync(binPath, process.argv.slice(2), { stdio: "inherit" });

if (result.error) {
  fail(`tenantguard: failed to execute binary at ${binPath}: ${result.error.message}`);
}

if (result.signal) {
  fail(`tenantguard: binary terminated by signal ${result.signal}`);
}

process.exit(result.status === null ? 1 : result.status);
