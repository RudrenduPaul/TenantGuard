# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added
- `tenantguard scan --format json`: a plain, schema-light structured output
  mode alongside `--format sarif`, for agents/scripts that want raw
  rule_id/status/location results without SARIF's tool/run/rule/taxonomy
  object model. Includes both PASS and FAIL findings (SARIF only emits FAIL
  as a result), plus a `summary.fail`/`summary.pass` count.

### Fixed
- SARIF output (`--format sarif`) now declares TA15 and TA16 in
  `runs[].tool.driver.rules`; both rules' results were already emitted but
  the rule-ID list backing that array had not been updated when TA15/TA16
  shipped, so SARIF consumers that key rule metadata off `driver.rules`
  (e.g. some code-scanning UIs) would not resolve those two rule IDs.
- PyPI wrapper (`tenantguard-cli` on PyPI, `python/src/tenantguard_cli/cli.py`):
  `checksums.txt.pem` and `checksums.txt.sig` downloaded from GitHub Releases
  are cosign's base64-encoded output, not raw PEM/DER bytes; the verifier was
  passing them straight to `load_pem_x509_certificate`/the Sigstore bundle
  builder without decoding first, so every install failed on first run with
  `could not parse checksums.txt.pem as a PEM certificate`. Both values are
  now base64-decoded before use, with regression tests covering the decode
  failure path. Affects all published versions up to and including 0.1.2;
  fixed here, pending a new release.
- npm package (`tenantguard-cli` on npm, `npm/tenantguard/`): the published
  package directory had no `README.md`, so `registry.npmjs.org` and the
  npmjs.com package page rendered no description at all. Added.
- `SECURITY.md` pointed to `security@tenantguard.dev`, a domain that does not
  exist (NXDOMAIN) -- any report sent there would silently bounce. Switched
  to GitHub's private vulnerability reporting (enabled on this repository),
  linked from `SECURITY.md`.

### Added (original)
- Initial `tenantguard scan` CLI: five tenant-isolation rules (TA01-TA05), each
  mapped to a confirmed, still-open GitHub issue in `goclaw`
  (#1163, #1070, #1217, #1227, #1216).
- OPA/Rego-embedded scan engine (`internal/policy/`), evaluated via prepared queries
  against a single merged `CollectedConfig` document per scan.
- Provisional HIPAA Security Rule Sec164.312 citation metadata on every FAIL finding
  (`internal/compliance/`), TenantGuard's own interpretation, not legal advice.
- SARIF 2.1.0 export (`internal/report/sarif.go`) via `owenrumney/go-sarif`, with a
  HIPAA taxonomy so citations round-trip through the `taxa`/rules schema.
- Human-readable terminal output showing both FAIL and PASS results per scan.
- `tenantguard scan --demo`, a bundled synthetic deployment reproducing all five
  rule violations, for a zero-setup first scan.
- GitHub Action wrapper (`action/`) for CI-triggered scans with SARIF upload.
- Distribution via Homebrew tap, `go install`, and GitHub Releases (GoReleaser,
  cross-platform, sigstore-signed, with an SBOM attached).
- TA10: best-effort per-agent config-override declaration completeness check —
  flags agents whose YAML entry doesn't explicitly declare a
  `workspace_restriction` or `sandbox_config` override. A static-config proxy
  for the runtime bug fixed in `goclaw` PR #145 (per-agent DB settings
  silently ignored because tool config was baked in at process startup); it
  cannot detect that Go-level bug itself, only under-specified config.
- TA12: a sixth, deployment-level rule checking that a deployment guarantees
  owner/sysadmin recovery access (a valid gateway-token-authenticated
  `system` account guaranteed treated as emergency sysadmin, and a declared
  recovery/reset command), mapped to `goclaw#954`, a maintainer-acknowledged
  CRITICAL design gap describing owner/sysadmin configuration with no
  guaranteed recovery path.
