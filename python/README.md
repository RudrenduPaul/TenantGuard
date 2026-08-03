# tenantguard-cli (PyPI)

**Find the tenant-isolation gap in your self-hosted, multi-tenant AI-agent platform before an auditor, or an attacker, does.**

This is the PyPI distribution of [TenantGuard](https://github.com/RudrenduPaul/TenantGuard), a command-line policy-as-code scanner, written in Go and built on OPA/Rego, that audits a self-hosted multi-tenant AI-agent platform's configuration for tenant-isolation defects: the class of bug where one tenant's agent, sandbox, cron job, or credential can reach or affect another tenant.

This package does not reimplement TenantGuard in Python. It resolves the correct prebuilt binary for your platform from TenantGuard's [GitHub Releases](https://github.com/RudrenduPaul/TenantGuard/releases) (published by goreleaser), verifies its SHA-256 checksum against the release's signed `checksums.txt`, caches it locally, and execs it, forwarding argv/stdio/exit code unchanged.

## Install

```bash
pip install tenantguard-cli
```

or run without installing:

```bash
uvx tenantguard-cli scan --demo
```

**Known issue (versions up to and including 0.1.2):** first run fails with `could not parse checksums.txt.pem as a PEM certificate` — the wrapper wasn't base64-decoding the cosign-produced certificate/signature release assets before parsing them. The fix is merged to `src/tenantguard_cli/cli.py` (with regression tests) but not yet in a released version. Use `npm install -g tenantguard-cli` or `go install` in the meantime, or watch for the next PyPI release.

Other distribution channels for TenantGuard: `npm install -g tenantguard-cli`, a Homebrew tap, `go install`, and GitHub Releases directly. See the [main README](https://github.com/RudrenduPaul/TenantGuard#readme) for details on each.

## Quickstart

```bash
tenantguard scan --demo
```

Zero setup: this scans a bundled synthetic deployment and prints real findings, including rule IDs, exact config locations, the upstream `goclaw` issue each rule maps to, and a provisional HIPAA citation. Scan a real deployment instead:

```bash
tenantguard scan --target ./deployment --format sarif --sarif-out tenantguard-report.sarif
```

Or emit plain JSON, for a script or agent that would rather parse a flat findings array than a SARIF document (implemented on `main`, not yet in the tagged release this package downloads — see [CLI Reference](#cli-reference) below):

```bash
tenantguard scan --target ./deployment --format json
```

## Features

TenantGuard scans a self-hosted, multi-tenant AI-agent deployment's configuration against 16 rules, each derived from a real, confirmed tenant-isolation failure mode. Every rule is fail-closed: an undeclared or ambiguous setting is a violation, not a silent pass.

- **16 fail-closed rules (TA01-TA16)** covering tenant isolation boundaries (sandbox/workspace mounts, cron bindings, channel/session identity), network and credential exposure (MCP tool SSRF, LLM provider connection SSRF, exec-tool secret leakage, credential-storage encryption), execution and approval hardening (exec-approval path scoping, container privilege), and identity/audit/recovery (creator identity capture, owner recovery, bridge signing).
- **SARIF 2.1.0 output** (`--format sarif`), schema-valid, ready for `github/codeql-action/upload-sarif` and GitHub code scanning.
- **Plain JSON output** (`--format json`) for a script or agent that wants a flat findings array, including every PASS alongside every FAIL, not just problems found.
- **Provisional HIPAA citations** on every finding (`--control hipaa`), mapped per rule. Marked provisional, see the FAQ below.
- **Zero-setup demo mode** (`--demo`) that scans a bundled synthetic deployment, no target config required.
- **MCP server mode** (`tenantguard mcp`), covered in full below.

## CLI Reference

TenantGuard has two subcommands: `scan` (the audit itself) and `mcp` (runs the same scan engine as an MCP server over stdio). There is no top-level `--help` or `--version` flag; running `tenantguard` with no arguments, `tenantguard --help`, or any first argument other than `scan` or `mcp` prints the usage lines below to stderr and exits `2`.

> **Release status:** `--format json` and the `mcp` subcommand are implemented on `main` but not yet in a tagged release. This package downloads the binary from the latest tagged GitHub Release, which currently only supports `--format terminal|sarif` and has no `mcp` subcommand. Build from source (`go install github.com/RudrenduPaul/TenantGuard/cmd/tenantguard@main`) to use either today.

```
usage: tenantguard scan [--target DIR | --demo] [--format terminal|sarif|json] [--control hipaa]
       tenantguard mcp
```

`tenantguard scan --help`:

```
Usage of scan:
  -control string
        compliance framework to cite (hipaa)
  -demo
        scan a bundled synthetic deployment instead of --target (zero setup)
  -format string
        output format: terminal, sarif, or json (default "terminal")
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

## MCP server (agent-native usage)

> **Not yet in a tagged release** (see the note under [CLI Reference](#cli-reference) above). Build from `main` to run `tenantguard mcp` today.

Everything above assumes a human typing `tenantguard scan` at a terminal. TenantGuard also runs as an MCP server, so an AI agent (a coding assistant, an ops agent, anything that speaks the Model Context Protocol) can call the scan engine directly as a tool call, instead of shelling out to the CLI and parsing text.

```bash
tenantguard mcp
```

This starts an MCP server on stdio and blocks until the client disconnects. It takes no flags or positional arguments. Under the hood it's a thin protocol adapter over the exact same collector-to-report pipeline the `scan` subcommand runs, so there's no separate rule-evaluation logic to keep in sync between the human CLI path and the agent-native path.

It exposes a single tool, `scan`, with three arguments that mirror the CLI's own flags:

| Argument | Maps to | Notes |
|---|---|---|
| `target` | `--target` | Required. Path to the deployment config directory to scan. |
| `format` | `--format` | Optional. `json`, `sarif`, or `terminal`. Defaults to `json` for MCP (the CLI itself defaults to `terminal`), since a calling agent almost always wants structured output. |
| `control` | `--control` | Optional. Only `hipaa` is recognized today; an empty value also defaults to `hipaa`, matching the CLI. |

For `json` and `sarif` output, the result is returned both as text and as MCP `StructuredContent`, so a client that wants to read fields directly (`rule_id`, `status`, `file`, `line`) doesn't have to re-parse the text block itself.

To register TenantGuard with an MCP-compatible client such as Claude Desktop, add it to the client's server config:

```json
{
  "mcpServers": {
    "tenantguard": {
      "command": "tenantguard",
      "args": ["mcp"]
    }
  }
}
```

This assumes `tenantguard` is already on your `PATH` (true after `pip install tenantguard-cli`). Before this shipped, the only way to run a scan was a human invoking the CLI directly. With `tenantguard mcp`, an agent can call `scan` as a tool, get structured findings back, and act on them in the same session.

## How this PyPI package differs from the npm package

The `tenantguard-cli` npm package ships six platform-specific `optionalDependencies`, each embedding a cosign-verified binary at publish time; no network access happens on an end user's `npm install`. A single pure-Python wheel can't embed six platform binaries the same way, so this package instead downloads the matching release archive the first time you run `tenantguard`, verifies its SHA-256 against the release's `checksums.txt` (itself cosign-signature-verified via the `sigstore` library before any digest inside it is trusted), and caches the verified binary locally per package version. Every run after the first is offline.

## What is TenantGuard and why does it exist

TenantGuard exists because a real, confirmed multi-tenant AI-agent platform (`goclaw`) has had multiple open, unresolved issues in exactly this category: a sandbox mount not scoped per tenant, a cross-agent authorization gap, an exec tool that leaks secrets through an indirect path, an approval bypass keyed on a filename instead of a real path scope, and an SSRF validation mismatch on saved tool URLs and LLM provider connections. No existing general-purpose IaC scanner (Checkov, Conftest, PolicyGuard) or AI-agent security scanner (AgentShield) checks for this specific failure category: cross-tenant isolation in a self-hosted, multi-agent deployment. TenantGuard fills that gap with 16 fail-closed rules, each traceable to a real, cited issue.

TenantGuard is not a generic Terraform/Kubernetes scanner and does not replace Checkov or Conftest for general cloud-infrastructure misconfiguration. It is scoped specifically to the tenant-isolation surface of self-hosted multi-tenant agent deployments.

## FAQ

**How is TenantGuard different from a generic IaC scanner like Checkov or Conftest?**
Checkov and Conftest scan general infrastructure-as-code (Terraform, Kubernetes, CloudFormation, and similar) for broad categories of misconfiguration. Neither ships a rule pack for multi-tenant AI-agent deployments. TenantGuard's 16 rules are purpose-built for that one surface: sandbox mounts, cron/agent bindings, MCP tool registrations, LLM provider connections, exec approvals, and channel/session identity, each derived from a real, cited defect.

**Does TenantGuard replace OPA or Conftest?**
No. TenantGuard's rules are written in Rego and TenantGuard bundles its own evaluation path; it is a purpose-built policy pack and CLI, not a general-purpose Rego test harness. If you need to test arbitrary structured config against arbitrary Rego policies, Conftest is the right general tool. TenantGuard is the right tool specifically for tenant-isolation checks on a multi-agent deployment.

**What does the HIPAA citation on each finding mean?**
Every finding is annotated with a related HIPAA Security Rule citation (e.g. Sec164.312(a)(1) Access Control) to help map a technical finding to a compliance control a reviewer may already track. These citations are marked provisional: they indicate a plausible mapping between the technical control and the cited HIPAA section, not a legal or audited compliance determination. Treat them as a starting point for your own compliance review, not a substitute for one.

**Does TenantGuard produce output a CI pipeline or GitHub code scanning can consume?**
Yes. `--format sarif --sarif-out <file>` produces a schema-valid SARIF 2.1.0 document with real result locations and messages. The repo's bundled GitHub Action runs a scan and uploads the SARIF report automatically.

**Why does TenantGuard have both `--format sarif` and `--format json`? Isn't SARIF already structured output?**
Yes, SARIF is a real, standard, machine-parseable format, and it is the right choice for CI/code-scanning integration. `--format json` exists for a different consumer: a script or agent that wants to parse `rule_id`/`status`/`file`/`line` directly, without walking SARIF's tool/run/rule/taxonomy object model first. It also reports every PASS alongside every FAIL, which SARIF deliberately does not. Not yet in a tagged release — see [CLI Reference](#cli-reference) above.

**Does this package need my own API keys or credentials?**
No. TenantGuard scans a local configuration directory (or, with `--target` pointing at a read-only credentialed admin API, a deployment's live state) and never sends any deployment data, config, or scan payload anywhere. There is no account, API key, or network service this package talks to at scan time, only the one-time binary download from GitHub Releases on first run.

**Is this package safe? How is the downloaded binary verified?**
Every download is checked against the release's SHA-256 `checksums.txt`, and that checksums file is itself verified via a cosign/Sigstore signature (keyless, GitHub Actions OIDC) before any digest inside it is trusted, closing the gap where a compromised checksums file and a compromised binary could otherwise pass a checksum-only check together. See `src/tenantguard_cli/cli.py` for the exact verification logic. **Note:** published versions up to and including 0.1.2 fail this verification step on every platform due to a base64-decoding bug (see [Install](#install) above); the fix is merged but not yet released.

**Can an AI agent run TenantGuard directly, without a human typing CLI commands?**
Yes, via `tenantguard mcp`, which starts an MCP server on stdio exposing the scan engine as a `scan` tool. See [MCP server (agent-native usage)](#mcp-server-agent-native-usage) above for the exact client config, tool arguments, and current release status.

**Is TenantGuard a library I can import into my own Python program?**
No. This package is a thin binary-fetching wrapper around the real TenantGuard Go binary, not a reimplementation. Everything you'd want to call programmatically is available either via the CLI's `--format json` output or via `tenantguard mcp`'s agent-native interface.

## License

Apache License 2.0, matching the main [TenantGuard](https://github.com/RudrenduPaul/TenantGuard) repository.
