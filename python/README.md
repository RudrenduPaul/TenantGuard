# tenantguard-cli (PyPI)

PyPI wrapper for [TenantGuard](https://github.com/RudrenduPaul/TenantGuard),
a tenant-isolation security-audit CLI for self-hosted multi-tenant AI-agent
platforms. This package does not reimplement TenantGuard in Python -- it
downloads the official prebuilt `tenantguard` binary for your platform from
TenantGuard's [GitHub Releases](https://github.com/RudrenduPaul/TenantGuard/releases)
(published by goreleaser), verifies its SHA-256 checksum, caches it locally,
and execs it.

## Install

```bash
pip install tenantguard-cli
```

or run without installing:

```bash
uvx tenantguard-cli scan --demo
```

## Usage

```bash
tenantguard scan --demo
tenantguard scan --format sarif
tenantguard scan --format json
```

See the main [TenantGuard README](https://github.com/RudrenduPaul/TenantGuard#readme)
for the full rule reference (TA01-TA16), SARIF/JSON output schema, and the
GitHub Action.

## How this differs from the npm package

The `tenantguard-cli` npm package ships six platform-specific
`optionalDependencies`, each embedding a cosign-verified binary at publish
time -- no network access happens on an end user's `npm install`. A single
pure-Python wheel can't embed six platform binaries the same way, so this
package instead downloads the matching release archive the first time you
run `tenantguard`, verifies its SHA-256 against the release's
`checksums.txt`, and caches the verified binary locally (per package
version) -- every run after that is offline. See `src/tenantguard_cli/cli.py`
for the exact verification logic.

Other distribution channels for TenantGuard: Homebrew, `go install`, and
GitHub Releases directly -- see the main README for details.

## License

Apache-2.0, matching the main TenantGuard repository.
