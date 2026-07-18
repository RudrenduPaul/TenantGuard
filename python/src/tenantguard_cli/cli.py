"""Runtime entry point for the `tenantguard` console script.

On first invocation for a given (package version, platform, arch), this
downloads the matching TenantGuard release archive from GitHub Releases,
verifies checksums.txt's Sigstore signature (keyless, GitHub Actions OIDC)
before trusting any digest inside it, verifies the archive against that
digest (SHA-256), extracts the binary into a local cache directory, then
execs it -- forwarding argv, stdio, and exit code unchanged. Subsequent
invocations reuse the cached binary; no network access happens once it's
cached.

Signature verification uses the `sigstore` PyPI package (a pure-Python
Sigstore client, see https://pypi.org/project/sigstore/), not the `cosign`
CLI binary that npm/scripts/fetch-binary.js shells out to. That script runs
only at *publish* time, on the maintainer's own CI runner, where installing
an extra CLI binary is a reasonable ask. This package's download happens on
the *end user's* machine at first run instead -- a single pure-Python wheel
can't embed all platform binaries the way npm's per-platform packages can --
so requiring end users to separately install `cosign` would be a real
usability regression. sigstore-python avoids that tradeoff: the same
verification guarantee (checksums.txt must carry a valid Sigstore signature
from this repo's own release workflow, keyless via GitHub Actions OIDC, with
certificate identity and issuer checked against the pinned RELEASE_TAG) with
no extra binary for the end user to install.

checksums.txt.sig and checksums.txt.pem (the same release assets the npm
script already consumes) are fetched alongside checksums.txt and verified
BEFORE any digest is parsed out of it. That ordering is what actually closes
the gap SHA-256-over-HTTPS alone leaves open: if checksums.txt and a
malicious archive were served together from a single compromised source,
they'd still agree with each other and pass a bare digest check. Requiring a
valid signature from the real release workflow first means an attacker would
also need to forge that signature, not just serve consistent bytes.
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

from cryptography.x509 import load_pem_x509_certificate
from sigstore._internal.rekor import _hashedrekord_from_parts
from sigstore.hashes import HashAlgorithm, Hashed
from sigstore.models import Bundle
from sigstore.verify import Verifier
from sigstore.verify import policy as sigstore_policy

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

# Same identity/issuer the release workflow (.github/workflows/release.yml)
# signs checksums.txt with, and that npm/scripts/fetch-binary.js's cosign
# check already verifies against -- keyless Sigstore signing via GitHub
# Actions OIDC, scoped to this exact release workflow run for this exact tag.
SIGSTORE_OIDC_ISSUER = "https://token.actions.githubusercontent.com"


def _sigstore_certificate_identity() -> str:
    return f"https://github.com/{REPO}/.github/workflows/release.yml@refs/tags/{RELEASE_TAG}"


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


def _build_sigstore_verifier() -> Verifier:
    """Split out so tests can monkeypatch it instead of hitting the real
    Sigstore trust root / TUF refresh."""
    return Verifier.production()


def _retrieve_sigstore_log_entry(verifier: Verifier, certificate, signature: bytes, hashed: Hashed):
    """Looks up the Rekor transparency-log entry matching a *detached*
    signature + certificate pair (i.e. separate .sig/.pem files, the same
    shape cosign produces and that checksums.txt.sig/.pem already are) --
    mirrors what sigstore-python's own CLI does internally for this exact
    "detached materials" case (see sigstore.verify.Verifier's `_rekor`
    attribute and its "ugly hack needed for verifying detached materials"
    comment). A `Bundle` built via `Bundle.from_parts` requires this log
    entry, so it has to be fetched before verification can proceed. Split out
    so tests can monkeypatch it instead of hitting the real transparency log.
    """
    return verifier._rekor.log.entries.retrieve.post(  # noqa: SLF001
        _hashedrekord_from_parts(certificate, signature, hashed)
    )


def _verify_checksums_signature(checksums_bytes: bytes, cert_pem_bytes: bytes, sig_bytes: bytes) -> None:
    """Verifies checksums.txt was signed by this repo's own release workflow
    via Sigstore keyless signing (GitHub Actions OIDC), using the pure-Python
    `sigstore` library. `cert_pem_bytes`/`sig_bytes` are the raw bytes
    downloaded from checksums.txt.pem / checksums.txt.sig -- the same release
    assets npm/scripts/fetch-binary.js's cosign check already consumes.

    Raises RuntimeError on any failure: a certificate that doesn't parse, no
    matching transparency-log entry, a signature that doesn't verify, or a
    certificate identity/issuer that doesn't match this exact release
    workflow run. Must be called, and must succeed, before any digest parsed
    out of checksums.txt is trusted.
    """
    try:
        certificate = load_pem_x509_certificate(cert_pem_bytes)
    except ValueError as exc:
        raise RuntimeError(
            f"tenantguard-cli: could not parse checksums.txt.pem as a PEM certificate: {exc}"
        ) from exc

    hashed = Hashed(algorithm=HashAlgorithm.SHA2_256, digest=hashlib.sha256(checksums_bytes).digest())
    verifier = _build_sigstore_verifier()

    try:
        log_entry = _retrieve_sigstore_log_entry(verifier, certificate, sig_bytes, hashed)
    except Exception as exc:
        raise RuntimeError(
            "tenantguard-cli: failed to look up checksums.txt's signature in the Sigstore "
            f"transparency log: {exc}"
        ) from exc

    if log_entry is None:
        raise RuntimeError(
            "tenantguard-cli: no matching Sigstore transparency log entry found for "
            "checksums.txt.sig/checksums.txt.pem -- refusing to trust checksums.txt."
        )

    try:
        bundle = Bundle.from_parts(certificate, sig_bytes, log_entry)
    except Exception as exc:
        raise RuntimeError(
            f"tenantguard-cli: could not assemble a Sigstore bundle for checksums.txt: {exc}"
        ) from exc

    verification_policy = sigstore_policy.Identity(
        identity=_sigstore_certificate_identity(),
        issuer=SIGSTORE_OIDC_ISSUER,
    )

    try:
        verifier.verify_artifact(checksums_bytes, bundle, verification_policy)
    except Exception as exc:
        raise RuntimeError(
            f"tenantguard-cli: Sigstore signature verification failed for checksums.txt: {exc}"
        ) from exc

    print(
        "tenantguard-cli: sigstore signature verified for checksums.txt "
        "(keyless, GitHub Actions OIDC)",
        file=sys.stderr,
    )


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
    checksums_sig_url = f"{checksums_url}.sig"
    checksums_cert_url = f"{checksums_url}.pem"

    print(f"tenantguard-cli: downloading {archive_url}", file=sys.stderr)
    archive_bytes = _fetch(archive_url)
    checksums_bytes = _fetch(checksums_url)
    checksums_sig_bytes = _fetch(checksums_sig_url)
    checksums_cert_bytes = _fetch(checksums_cert_url)

    _verify_checksums_signature(checksums_bytes, checksums_cert_bytes, checksums_sig_bytes)

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
