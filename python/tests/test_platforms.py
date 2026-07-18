import pytest

from tenantguard_cli.platforms import (
    UnsupportedPlatformError,
    archive_ext,
    archive_name,
    binary_name,
    resolve_goarch,
    resolve_goos,
)


def test_resolve_goos_known_platforms():
    assert resolve_goos("linux") == "linux"
    assert resolve_goos("darwin") == "darwin"
    assert resolve_goos("win32") == "windows"
    assert resolve_goos("cygwin") == "windows"


def test_resolve_goos_unsupported():
    with pytest.raises(UnsupportedPlatformError):
        resolve_goos("freebsd")


def test_resolve_goarch_known_machines():
    assert resolve_goarch("x86_64") == "amd64"
    assert resolve_goarch("amd64") == "amd64"
    assert resolve_goarch("arm64") == "arm64"
    assert resolve_goarch("aarch64") == "arm64"
    # case-insensitive
    assert resolve_goarch("X86_64") == "amd64"


def test_resolve_goarch_unsupported():
    with pytest.raises(UnsupportedPlatformError):
        resolve_goarch("riscv64")


def test_archive_ext():
    assert archive_ext("windows") == "zip"
    assert archive_ext("linux") == "tar.gz"
    assert archive_ext("darwin") == "tar.gz"


def test_binary_name():
    assert binary_name("windows") == "tenantguard.exe"
    assert binary_name("linux") == "tenantguard"
    assert binary_name("darwin") == "tenantguard"


def test_archive_name_matches_goreleaser_template():
    # Matches .goreleaser.yml's name_template: "{{ .ProjectName }}_{{ .Os }}_{{ .Arch }}"
    assert archive_name("tenantguard", "darwin", "arm64") == "tenantguard_darwin_arm64.tar.gz"
    assert archive_name("tenantguard", "linux", "amd64") == "tenantguard_linux_amd64.tar.gz"
    assert archive_name("tenantguard", "windows", "amd64") == "tenantguard_windows_amd64.zip"
