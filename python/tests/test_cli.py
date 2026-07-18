import hashlib

from tenantguard_cli.cli import _parse_checksums, _sha256_hex


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
