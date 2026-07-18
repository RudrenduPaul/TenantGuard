"""tenantguard-cli: a thin PyPI wrapper around the TenantGuard Go binary.

This package does not reimplement TenantGuard in Python. It resolves the
correct prebuilt binary for the running platform from TenantGuard's GitHub
Releases (published by goreleaser), caches it locally, and execs it,
forwarding argv/stdio/exit-code unchanged. See ``tenantguard_cli.cli`` and
``tenantguard_cli.platforms`` for the implementation.
"""

__version__ = "0.1.2"

# The GitHub release tag this package version is pinned to. Normally kept in
# lockstep with __version__ (and with the npm wrapper's RELEASE_TAG in
# npm/scripts/fetch-binary.js) -- a new TenantGuard Go release means a new
# tenantguard-cli release pinned to the matching tag, never a silent
# "latest" resolution at install or run time. 0.1.2 is a Python-package-only
# release (README/metadata fixes, no Go binary change), so it stays pinned to
# the last real Go release tag rather than a non-existent "v0.1.2" one.
RELEASE_TAG = "v0.1.1"
