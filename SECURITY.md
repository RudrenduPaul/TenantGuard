# Security Policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository: go to the
[Security tab](https://github.com/RudrenduPaul/TenantGuard/security/advisories/new)
and click "Report a vulnerability." This opens a private advisory only the
maintainer can see, with a description of the issue and steps to reproduce. We
aim to acknowledge reports within **48 hours** and to ship a fix or mitigation
plan within 14 days for confirmed high-severity issues.

Please do not open a public GitHub issue for security reports. Use the private
advisory flow above so a fix can ship before the details are public.

## Scope

In scope:
- The `tenantguard` CLI and its rule pack (`internal/policy/`)
- The SARIF and terminal report writers
- The GitHub Action wrapper (`action/`)
- The release/build pipeline (GoReleaser config, CI workflows)

Out of scope:
- Vulnerabilities in `goclaw` or other platforms TenantGuard scans (report those
  upstream, to the platform's own maintainers)
- The hosted continuous-monitoring tier (does not exist yet, nothing to report)

## Supported versions

Only the latest tagged release is supported. There is no long-term-support branch
at this stage of the project.

## A note on what TenantGuard's own findings mean

A clean TenantGuard scan (`0 FAIL`) means the target deployment passed the current
rule set. It is not a guarantee of general security, and it is not a HIPAA
compliance certification. See the README and `internal/compliance/hipaa.go` for the
limits of the HIPAA control-mapping metadata.
