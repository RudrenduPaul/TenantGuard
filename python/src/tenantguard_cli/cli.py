"""Runtime entry point for the `tenantguard` console script.

On first invocation for a given (package version, platform, arch), this
downloads the matching TenantGuard release archive from GitHub Releases,
verifies it against the release's checksums.txt (SHA-256), extracts the
binary into a local cache directory, then execs it -- forwarding argv,
stdio, and exit code unchanged. Subsequent invocations reuse the cached
binary; no network access happens once it's cached.

This intentionally does not perform the cosign/sigstore verification that
npm/scripts/fetch-binary.js does in this same repo: that script runs only
at *publish* time, on the maintainer's own CI runner, to verify the archive
before embedding it into the platform npm packages that actually ship to
end users -- npm end users never run cosign themselves, they get npm
registry integrity guarantees instead. This package has no such publish-time
embedding step (a single pure-Python wheel can't hold six platform
binaries), so the download happens on the *end user's* machine instead. The
SHA-256 check against checksums.txt, fetched over HTTPS from
github.com/.../releases, is the trust boundary here -- the same baseline
used by most Go-binary installer scripts. Users who want the stronger
cosign-verified path already have it: the Homebrew tap and the npm package
both embed cosign-verified binaries.
"""

from __future__ import annotations

import hashlib
import io
import os
import stat
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from . import RELEASE_TAG, __version__
from .platforms import (
    UnsupportedPlatformError,
    archive_ext,
    archive_name,
    binary_name,
    resolve_goarch,
    resolve_goos,
)

REPO = "RudrenduPaul/TenantGuard"
PROJECT_NAME = "tenantguard"
RELEASE_BASE = f"https://github.com/{REPO}/releases/download/{RELEASE_TAG}"
USER_AGENT = "tenantguard-cli-pypi-wrapper"
REQUEST_TIMEOUT_SECONDS = 30


def _cache_dir() -> Path:
    """Version-scoped cache directory. A new pinned RELEASE_TAG (i.e. a new
    tenantguard-cli release) gets its own subdirectory, so upgrading this
    package always re-downloads rather than silently reusing a stale binary.
    """
    base = os.environ.get("TENANTGUARD_CLI_CACHE_DIR")
    if base:
        root = Path(base)
    elif sys.platform == "win32":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "tenantguard-cli"
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Caches" / "tenantguard-cli"
    else:
        xdg = os.environ.get("XDG_CACHE_HOME")
        root = Path(xdg) / "tenantguard-cli" if xdg else Path.home() / ".cache" / "tenantguard-cli"
    return root / __version__


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"tenantguard-cli: GET {url} failed: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"tenantguard-cli: GET {url} failed: {exc.reason}") from exc


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_checksums(text: str) -> dict[str, str]:
    """checksums.txt lines look like "<64 hex chars>  <filename>" (goreleaser's
    default sha256sum-compatible format; tolerate an optional leading "*")."""
    checksums: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, filename = parts
        digest = digest.strip().lower()
        filename = filename.lstrip("*").strip()
        if len(digest) == 64:
            checksums[filename] = digest
    return checksums


def _extract_binary(archive_bytes: bytes, ext: str, target_basename: str) -> bytes:
    if ext == "zip":
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
            for name in zf.namelist():
                if os.path.basename(name) == target_basename:
                    return zf.read(name)
    else:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
            for member in tf.getmembers():
                if os.path.basename(member.name) == target_basename:
                    extracted = tf.extractfile(member)
                    if extracted is None:
                        break
                    return extracted.read()
    raise RuntimeError(
        f"tenantguard-cli: could not find '{target_basename}' inside the downloaded archive."
    )


def ensure_binary() -> Path:
    """Returns the path to a verified, cached tenantguard binary for the
    current platform, downloading and extracting it first if needed.
    """
    goos = resolve_goos()
    goarch = resolve_goarch()
    bin_name = binary_name(goos)

    cache_dir = _cache_dir()
    cached_path = cache_dir / bin_name
    if cached_path.is_file() and os.access(cached_path, os.X_OK):
        return cached_path

    asset_name = archive_name(PROJECT_NAME, goos, goarch)
    archive_url = f"{RELEASE_BASE}/{asset_name}"
    checksums_url = f"{RELEASE_BASE}/checksums.txt"

    print(f"tenantguard-cli: downloading {archive_url}", file=sys.stderr)
    archive_bytes = _fetch(archive_url)
    checksums_bytes = _fetch(checksums_url)

    checksums = _parse_checksums(checksums_bytes.decode("utf-8", errors="replace"))
    expected_digest = checksums.get(asset_name)
    if not expected_digest:
        raise RuntimeError(
            f"tenantguard-cli: no checksum entry for '{asset_name}' in {RELEASE_TAG}'s "
            "checksums.txt -- refusing to proceed."
        )

    actual_digest = _sha256_hex(archive_bytes)
    if actual_digest != expected_digest:
        raise RuntimeError(
            f"tenantguard-cli: checksum mismatch for {asset_name}: "
            f"expected {expected_digest}, got {actual_digest}. Refusing to extract."
        )
    print(f"tenantguard-cli: checksum verified for {asset_name}", file=sys.stderr)

    binary_data = _extract_binary(archive_bytes, ext=archive_ext(goos), target_basename=bin_name)
    if not binary_data:
        raise RuntimeError(f"tenantguard-cli: extracted an empty '{bin_name}' from {asset_name}.")

    cache_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = cached_path.with_suffix(cached_path.suffix + ".tmp")
    tmp_path.write_bytes(binary_data)
    if sys.platform != "win32":
        current_mode = tmp_path.stat().st_mode
        tmp_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    tmp_path.replace(cached_path)

    print(f"tenantguard-cli: cached verified binary at {cached_path}", file=sys.stderr)
    return cached_path


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        binary_path = ensure_binary()
    except UnsupportedPlatformError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    result = subprocess.run([str(binary_path), *argv])
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
