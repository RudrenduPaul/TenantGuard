# tenantguard

Audit a self-hosted, multi-tenant AI-agent deployment for tenant-isolation defects, before an auditor, or an attacker, finds them for you.

    brew install RudrenduPaul/homebrew-tap/tenantguard
    tenantguard scan --demo

---

Drift, a different AI agent platform, shut down in March 2026 after an OAuth breach that affected more than 700 organizations. That kind of failure, one tenant reaching into another tenant's data or agents through a platform-level gap, is not hypothetical. It already happened once in this exact category.

goclaw, a genuinely useful self-hosted multi-tenant agent platform with more than 3,400 stars, has five open, confirmed issues that describe the same failure mode in miniature: a sandbox workspace mount that isn't scoped per tenant, a cross-agent authorization gap that lets a scheduled job reach a foreign tenant's agent, an exec tool that can leak environment secrets through an indirect path, an approval bypass keyed on a filename instead of a real path scope, and an SSRF validation mismatch on saved tool URLs. All five were still open the day this tool was written. None of them have accumulated much visible reaction yet, most were filed within the last few months, but each one is real, reproducible, and unfixed.

tenantguard checks for exactly these five patterns, and the broader category of tenant-isolation defect they represent, in any self-hosted multi-tenant agent deployment, not just goclaw.

## What it does

    tenantguard scan --target ./deployment/config

    [FAIL]  TA01 sandbox/workspace mount path is not scoped per-tenant
      config/sandbox.yml:8
      Maps to: goclaw#1163 | HIPAA Sec164.312(a)(1) Access Control (provisional)

    Summary: 1 FAIL, 4 PASS

Every finding names the exact config field at fault, the upstream issue it reproduces where one exists, and, if you're running this in a healthcare context, the specific HIPAA Security Rule technical safeguard it relates to. No deployment data or scan payload leaves the machine you run this on.

## Try it in under a minute, no setup

    tenantguard scan --demo

`--demo` runs the same five checks against a bundled synthetic deployment (reusing the exact fixtures the test suite is built on) so you can see a real finding, with a real file:line and a real HIPAA citation, without needing your own goclaw deployment on hand first.

## The six checks

| Rule | What it catches | Maps to |
|---|---|---|
| TA01 | Sandbox/workspace mount not scoped per tenant | `goclaw#1163` |
| TA02 | MCP tool URL targets a private/loopback address with no declared SSRF validation | `goclaw#1070` |
| TA03 | A scheduled job's target agent belongs to a different tenant, or doesn't exist at all | `goclaw#1217` |
| TA04 | An exec tool denies direct env-dump reads but not indirect ones (e.g. a shell running `jq $ENV`) | `goclaw#1227` |
| TA05 | An exec-approval "allow-always" entry is keyed on basename only, not a full path | `goclaw#1216` |
| TA11 | Channel/session device identity (e.g. a WhatsApp device session) is shared across channel_instances declaring different tenants | `goclaw#1064` |

Every rule has a labeled vulnerable fixture and a labeled clean fixture in `internal/policy/testdata/`, so the detection claim above is reproducible: `go test ./internal/policy/... -v`.

## How it's different from general IaC/config scanners

**Trivy** and **Conftest** are both excellent, general-purpose tools we build directly on top of the same ideas, Conftest in particular runs on the identical OPA/Rego engine tenantguard embeds. Neither ships a rule pack for self-hosted multi-tenant AI-agent platforms; you'd write all five of these checks from scratch yourself.

**Checkov** already ships built-in HIPAA-mapped policies, and does it well, but for cloud infrastructure resources (VPCs, S3 buckets, IAM roles), not for AI-agent tenant-isolation defects. Its compliance mapping doesn't cover this problem at all today.

tenantguard's whole reason to exist is the narrow overlap those tools don't cover: tenant-isolation-specific rules for self-hosted AI-agent platforms, with findings that speak the regulatory language a health-tech compliance officer actually reads.

| | tenantguard | Trivy | Conftest | Checkov |
|---|---|---|---|---|
| Built-in tenant-isolation rules for AI-agent platforms | 6 | 0 | 0 | 0 |
| HIPAA-mapped findings, this problem | Yes (provisional) | No | No | No |
| HIPAA-mapped findings, cloud IaC | No | No | No | Yes |
| Distribution | single static binary | single static binary | single static binary | Python package |
| Rule engine | OPA/Rego (embedded) | bespoke | OPA/Rego | bespoke, graph-based |

Sources: [Trivy docs](https://trivy.dev/docs/latest/getting-started/), [Conftest on GitHub](https://github.com/open-policy-agent/conftest), [Checkov compliance framework docs](https://www.checkov.io/).

## Measured, not asserted

- **Zero-setup scan:** `tenantguard scan --demo` completes in well under a second on a
  normal laptop (measured: ~0.01s of actual CPU time; wall-clock is dominated by
  process startup, not scanning).
- **Binary:** ~31MB, statically linked, no runtime dependency beyond standard OS
  system libraries (verified with `otool -L` / `ldd`). OPA and the SARIF library are
  embedded as Go modules, not separate tools you install.
- **Rule coverage:** every one of the 6 rules has both a true-positive and a
  true-negative test against a real fixture (`go test ./internal/policy/... -v`).
  Reproduce it yourself, don't take our word for it.

## GitHub Action

    - uses: RudrenduPaul/TenantGuard/action@main
      with:
        target: ./deployment/config
        version: v0.1.0 # pin this in your own workflow

Runs the scan in CI and uploads the SARIF report via `github/codeql-action/upload-sarif`, so findings show up as code-scanning alerts on your PRs.

## Self-host, always

All scans run against your own configuration. No deployment data, scan payload, or finding leaves the machine running the CLI. The scanner is free and stays free.

**Important:** a clean scan means your deployment passed tenantguard's current rule set. It is not a HIPAA compliance certification, and the control-mapping metadata is our own interpretation of the Security Rule's technical safeguards, not legal advice. Treat it as a strong signal, not a substitute for your own compliance counsel.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a new rule. Every rule needs both a vulnerable and a clean fixture before it ships.

## License

Apache 2.0. Self-host is free forever.
