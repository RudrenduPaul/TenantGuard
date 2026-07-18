"""tenantguard-cli: a thin PyPI wrapper around the TenantGuard Go binary.

This package does not reimplement TenantGuard in Python. It resolves the
correct prebuilt binary for the running platform from TenantGuard's GitHub
Releases (published by goreleaser), caches it locally, and execs it,
forwarding argv/stdio/exit-code unchanged. See ``tenantguard_cli.cli`` and
``tenantguard_cli.platforms`` for the implementation.
"""

__version__ = "0.1.1"

# The GitHub release tag this package version is pinned to. Kept in lockstep
# with __version__ (and with the npm wrapper's RELEASE_TAG in
# npm/scripts/fetch-binary.js) -- a new TenantGuard release means a new
# tenantguard-cli release pinned to the matching tag, never a silent
# "latest" resolution at install or run time.
RELEASE_TAG = f"v{__version__}"
