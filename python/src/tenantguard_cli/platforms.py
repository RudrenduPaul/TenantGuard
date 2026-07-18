"""Pure platform/arch resolution logic, kept separate from cli.py so it can
be unit tested without touching the network or the filesystem.

Mirrors the goreleaser build matrix in .goreleaser.yml (goos: linux, darwin,
windows / goarch: amd64, arm64) and the archive naming template
"{{ .ProjectName }}_{{ .Os }}_{{ .Arch }}" -- the same convention the npm
wrapper's optionalDependency package names / npm/scripts/fetch-binary.js
already rely on for this exact repo.
"""

from __future__ import annotations

import platform
import sys

# sys.platform -> goreleaser GOOS
_GOOS_MAP = {
    "linux": "linux",
    "darwin": "darwin",
    "win32": "windows",
    "cygwin": "windows",
}

# platform.machine() (lowercased) -> goreleaser GOARCH
_GOARCH_MAP = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "arm64": "arm64",
    "aarch64": "arm64",
}


class UnsupportedPlatformError(RuntimeError):
    """Raised when the running machine has no matching TenantGuard release asset."""


def resolve_goos(sys_platform: str = sys.platform) -> str:
    goos = _GOOS_MAP.get(sys_platform)
    if goos is None:
        raise UnsupportedPlatformError(
            f"tenantguard-cli: unsupported platform '{sys_platform}'. "
            f"Supported: {sorted(set(_GOOS_MAP.values()))}."
        )
    return goos


def resolve_goarch(machine: str | None = None) -> str:
    machine = (machine if machine is not None else platform.machine()).lower()
    goarch = _GOARCH_MAP.get(machine)
    if goarch is None:
        raise UnsupportedPlatformError(
            f"tenantguard-cli: unsupported CPU architecture '{machine}'. "
            f"Supported: {sorted(set(_GOARCH_MAP.values()))}."
        )
    return goarch


def archive_ext(goos: str) -> str:
    return "zip" if goos == "windows" else "tar.gz"


def binary_name(goos: str, base_name: str = "tenantguard") -> str:
    return f"{base_name}.exe" if goos == "windows" else base_name


def archive_name(project_name: str, goos: str, goarch: str) -> str:
    """Matches the .goreleaser.yml archive name_template:
    "{{ .ProjectName }}_{{ .Os }}_{{ .Arch }}" plus the format extension.
    """
    return f"{project_name}_{goos}_{goarch}.{archive_ext(goos)}"
