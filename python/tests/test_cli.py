import hashlib

import pytest

from tenantguard_cli import cli
from tenantguard_cli.cli import _parse_checksums, _sha256_hex, _verify_checksums_signature


def test_parse_checksums_standard_format():
    text = (
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  "
        "tenantguard_linux_amd64.tar.gz\n"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  "
        "tenantguard_darwin_arm64.tar.gz\n"
    )
    checksums = _parse_checksums(text)
    assert checksums["tenantguard_linux_amd64.tar.gz"] == "a" * 64
    assert checksums["tenantguard_darwin_arm64.tar.gz"] == "b" * 64


def test_parse_checksums_tolerates_leading_star_and_blank_lines():
    text = "\n" + "c" * 64 + "  *tenantguard_windows_amd64.zip\n\n"
    checksums = _parse_checksums(text)
    assert checksums["tenantguard_windows_amd64.zip"] == "c" * 64


def test_parse_checksums_ignores_malformed_lines():
    checksums = _parse_checksums("not-a-checksum-line\n")
    assert checksums == {}


def test_sha256_hex_matches_hashlib():
    data = b"tenantguard test payload"
    assert _sha256_hex(data) == hashlib.sha256(data).hexdigest()


# --- checksums.txt Sigstore signature verification --------------------------
#
# These tests never touch the real Sigstore transparency log or Fulcio trust
# root: they monkeypatch the seams `_verify_checksums_signature` calls out to
# (certificate parsing, verifier construction, the Rekor log-entry lookup,
# and bundle assembly), so only the actual policy-check call --
# `Verifier.verify_artifact` -- is exercised, via a fake standing in for it.


class _FakeVerifier:
    """Stand-in for sigstore.verify.Verifier. Records every call made to
    verify_artifact (so tests can assert what identity/issuer policy was
    checked against) and either succeeds or raises whatever exception the
    test configures, exactly like the real Verifier would on a rejected
    signature or an identity/issuer mismatch."""

    def __init__(self, raises: Exception | None = None):
        self.raises = raises
        self.calls = []

    def verify_artifact(self, input_, bundle, policy):
        self.calls.append((input_, bundle, policy))
        if self.raises is not None:
            raise self.raises


def _patch_sigstore_plumbing(monkeypatch, verifier, *, log_entry=object(), bundle=object()):
    """Bypasses everything upstream of the policy check -- PEM parsing, the
    Rekor transparency-log lookup, and Sigstore bundle assembly -- with
    lightweight stand-ins, since none of those are what this test suite is
    verifying: they're sigstore-python's own responsibility, already covered
    by that library's tests. What this module owns, and what these tests
    verify, is that `ensure_binary()`'s digest never gets trusted until
    `Verifier.verify_artifact` succeeds against the right identity/issuer.
    """
    monkeypatch.setattr(cli, "load_pem_x509_certificate", lambda pem: object())
    monkeypatch.setattr(cli, "_build_sigstore_verifier", lambda: verifier)
    monkeypatch.setattr(cli, "_retrieve_sigstore_log_entry", lambda *a, **k: log_entry)
    monkeypatch.setattr(cli.Bundle, "from_parts", staticmethod(lambda *a, **k: bundle))


def _assert_policy_matches_pinned_identity(checked_policy) -> None:
    """sigstore.verify.policy.Identity stores its fields as private
    attributes (`_identity`, `_issuer._value`) rather than a public API --
    reach into them here (test-only) to confirm _verify_checksums_signature
    builds its policy from the pinned RELEASE_TAG-scoped identity and the
    GitHub Actions OIDC issuer, not something looser."""
    assert checked_policy._identity == cli._sigstore_certificate_identity()
    assert checked_policy._issuer._value == cli.SIGSTORE_OIDC_ISSUER


def test_sigstore_certificate_identity_matches_release_workflow():
    assert cli._sigstore_certificate_identity() == (
        f"https://github.com/{cli.REPO}/.github/workflows/release.yml@refs/tags/{cli.RELEASE_TAG}"
    )
    assert cli.SIGSTORE_OIDC_ISSUER == "https://token.actions.githubusercontent.com"


def test_verify_checksums_signature_success_checks_correct_identity_and_issuer(monkeypatch):
    verifier = _FakeVerifier(raises=None)
    _patch_sigstore_plumbing(monkeypatch, verifier)

    # Should not raise.
    _verify_checksums_signature(b"checksums.txt contents", b"-----BEGIN CERTIFICATE-----", b"signature-bytes")

    assert len(verifier.calls) == 1
    checked_input, _checked_bundle, checked_policy = verifier.calls[0]
    assert checked_input == b"checksums.txt contents"
    _assert_policy_matches_pinned_identity(checked_policy)


def test_verify_checksums_signature_rejects_tampered_checksums(monkeypatch):
    """A checksums.txt that was tampered with after signing no longer
    matches the signature that was computed over the original bytes --
    sigstore-python's verify_artifact raises VerificationError for this, and
    that must surface as a RuntimeError, matching this module's error style,
    before any digest inside checksums.txt is ever trusted."""
    from sigstore.errors import VerificationError

    verifier = _FakeVerifier(raises=VerificationError("Signature is invalid for input"))
    _patch_sigstore_plumbing(monkeypatch, verifier)

    with pytest.raises(RuntimeError, match="Sigstore signature verification failed"):
        _verify_checksums_signature(b"tampered checksums.txt contents", b"-----BEGIN CERTIFICATE-----", b"sig")


def test_verify_checksums_signature_rejects_wrong_identity_or_issuer(monkeypatch):
    """A certificate signed by a different workflow/repo/tag, or issued by a
    different OIDC issuer than GitHub Actions, must be rejected even if the
    signature itself is otherwise cryptographically valid -- this is what
    the certificate-identity/issuer policy check exists for. sigstore-python
    raises VerificationError for a policy mismatch too (from inside
    verify_artifact's common-signing-cert checks); it must still surface as
    a RuntimeError here."""
    from sigstore.errors import VerificationError

    verifier = _FakeVerifier(
        raises=VerificationError(
            "Certificate's SANs do not match the expected identity, or the "
            "certificate's issuer extension does not match the expected issuer"
        )
    )
    _patch_sigstore_plumbing(monkeypatch, verifier)

    with pytest.raises(RuntimeError, match="Sigstore signature verification failed"):
        _verify_checksums_signature(b"checksums.txt contents", b"-----BEGIN CERTIFICATE-----", b"sig")

    # The policy actually checked was still the pinned identity/issuer, not
    # something looser -- confirms the rejection came from that policy, not
    # a coincidentally-broad one that would have let a wrong cert through.
    assert len(verifier.calls) == 1
    _, _, checked_policy = verifier.calls[0]
    _assert_policy_matches_pinned_identity(checked_policy)


def test_verify_checksums_signature_rejects_missing_transparency_log_entry(monkeypatch):
    """No matching Rekor entry (e.g. checksums.txt.sig/.pem weren't actually
    produced by a real Sigstore signing operation) must fail loudly rather
    than silently skipping straight to the SHA-256 check."""
    verifier = _FakeVerifier(raises=None)
    _patch_sigstore_plumbing(monkeypatch, verifier, log_entry=None)

    with pytest.raises(RuntimeError, match="no matching Sigstore transparency log entry"):
        _verify_checksums_signature(b"checksums.txt contents", b"-----BEGIN CERTIFICATE-----", b"sig")

    # verify_artifact must never be reached without a log entry to build a bundle from.
    assert verifier.calls == []


def test_verify_checksums_signature_rejects_unparseable_certificate(monkeypatch):
    """A missing/corrupt checksums.txt.pem (e.g. the signing step never ran,
    or the release asset wasn't published) must fail loudly with a clear
    error rather than crash on an unhandled exception."""

    def _raise_value_error(_pem):
        raise ValueError("Unable to load PEM file")

    monkeypatch.setattr(cli, "load_pem_x509_certificate", _raise_value_error)

    with pytest.raises(RuntimeError, match="could not parse checksums.txt.pem"):
        _verify_checksums_signature(b"checksums.txt contents", b"not a real certificate", b"sig")
