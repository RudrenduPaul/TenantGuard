# tenantguard-cli (npm)

**Find the tenant-isolation gap in your self-hosted, multi-tenant AI-agent platform before an auditor, or an attacker, does.**

This is the npm distribution of [TenantGuard](https://github.com/RudrenduPaul/TenantGuard), a command-line policy-as-code scanner, written in Go and built on OPA/Rego, that audits a self-hosted multi-tenant AI-agent platform's configuration for tenant-isolation defects: the class of bug where one tenant's agent, sandbox, cron job, or credential can reach or affect another tenant.

This package does not reimplement TenantGuard in JavaScript. It is a thin `bin` shim over a platform-specific binary package (e.g. `tenantguard-darwin-arm64`) installed as an npm `optionalDependency`, cosign-verified at publish time — no network download or verification step happens on your machine at install time.

## Install

```bash
npm install -g tenantguard-cli
```

npm resolves the matching platform package automatically (macOS x64/arm64, Linux x64/arm64, Windows x64/arm64) and puts a `tenantguard` command on your `PATH`.

Other distribution channels for TenantGuard: `pip install tenantguard-cli`, `go install`, and GitHub Releases directly. See the [main README](https://github.com/RudrenduPaul/TenantGuard#readme) for details on each.

## Quickstart

```bash
tenantguard scan --demo
```

Zero setup: this scans a bundled synthetic deployment and prints real findings, including rule IDs, exact config locations, the upstream `goclaw` issue each rule maps to, and a provisional HIPAA citation. Scan a real deployment instead:

```bash
tenantguard scan --target ./deployment --format sarif --sarif-out tenantguard-report.sarif
```

## Features

TenantGuard scans a self-hosted, multi-tenant AI-agent deployment's configuration against 16 rules, each derived from a real, confirmed tenant-isolation failure mode. Every rule is fail-closed: an undeclared or ambiguous setting is a violation, not a silent pass.

- **16 fail-closed rules (TA01-TA16)** covering tenant isolation boundaries (sandbox/workspace mounts, cron bindings, channel/session identity), network and credential exposure (MCP tool SSRF, LLM provider connection SSRF, exec-tool secret leakage, credential-storage encryption), execution and approval hardening (exec-approval path scoping, container privilege), and identity/audit/recovery (creator identity capture, owner recovery, bridge signing).
- **SARIF 2.1.0 output** (`--format sarif`), schema-valid, ready for `github/codeql-action/upload-sarif` and GitHub code scanning.
- **Provisional HIPAA citations** on every finding (`--control hipaa`), mapped per rule. Marked provisional, see the FAQ below.
- **Zero-setup demo mode** (`--demo`) that scans a bundled synthetic deployment, no target config required.

## CLI Reference

```
usage: tenantguard scan [--target DIR | --demo] [--format terminal|sarif] [--control hipaa]
```

`tenantguard scan --help`:

```
Usage of scan:
  -control string
    	compliance framework to cite (hipaa)
  -demo
    	scan a bundled synthetic deployment instead of --target (zero setup)
  -format string
    	output format: terminal or sarif (default "terminal")
  -sarif-out string
    	file to write SARIF output to when --format=sarif (default "tenantguard-report.sarif")
  -target string
    	path to the deployment config directory to scan
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Clean scan, no findings |
| `1` | Scan ran successfully, findings present |
| `2` | Scan or usage error |

`--format json` and a `tenantguard mcp` MCP-server subcommand are implemented on the project's `main` branch but not yet in the tagged release this package installs. See the [main README](https://github.com/RudrenduPaul/TenantGuard#readme) for full details and current release status.

## FAQ

**How is TenantGuard different from a generic IaC scanner like Checkov or Conftest?**
Checkov and Conftest scan general infrastructure-as-code (Terraform, Kubernetes, CloudFormation, and similar) for broad categories of misconfiguration. Neither ships a rule pack for multi-tenant AI-agent deployments. TenantGuard's 16 rules are purpose-built for that one surface: sandbox mounts, cron/agent bindings, MCP tool registrations, LLM provider connections, exec approvals, and channel/session identity, each derived from a real, cited defect.

**What does the HIPAA citation on each finding mean?**
Every finding is annotated with a related HIPAA Security Rule citation (e.g. Sec164.312(a)(1) Access Control) to help map a technical finding to a compliance control a reviewer may already track. These citations are marked provisional: they indicate a plausible mapping between the technical control and the cited HIPAA section, not a legal or audited compliance determination. Treat them as a starting point for your own compliance review, not a substitute for one.

**Does TenantGuard produce output a CI pipeline or GitHub code scanning can consume?**
Yes. `--format sarif --sarif-out <file>` produces a schema-valid SARIF 2.1.0 document with real result locations and messages. The repo's bundled GitHub Action runs a scan and uploads the SARIF report automatically.

**Is there a PyPI package?**
Yes, `tenantguard-cli` is also live on PyPI. See the [main README](https://github.com/RudrenduPaul/TenantGuard#readme) for current status of both distribution channels.

**Is TenantGuard a library I can import into my own program?**
No. This package is a thin `bin` wrapper around the platform-specific TenantGuard Go binary, not a reimplementation.

## License

Apache License 2.0, matching the main [TenantGuard](https://github.com/RudrenduPaul/TenantGuard) repository. See [LICENSE](https://github.com/RudrenduPaul/TenantGuard/blob/main/LICENSE).
