# CLAUDE.md -- tenantguard

## Project Identity

- **Idea:** Narrow, open-source tenant-isolation security-audit CLI for self-hosted
  multi-tenant AI-agent deployments (starting with goclaw), with HIPAA-mapped findings
  as the initial vertical wedge -- free/OSS scanner, plus a paid hosted continuous-
  monitoring/compliance-report tier for health-tech security and compliance teams.
- **Repo:** github.com/RudrenduPaul/TenantGuard
- **Module path:** github.com/RudrenduPaul/TenantGuard
- **Distribution:** single static Go binary (Homebrew tap, `go install`), plus a
  GitHub Action wrapper for CI-triggered scans
- **Language:** Go 1.26+ -- zero-runtime-dependency distribution for air-gapped/
  access-controlled environments, matching Trivy/grype conventions
- **Scan engine:** Open Policy Agent, embedded as a Go library
  (`github.com/open-policy-agent/opa/v1/rego`), not a bespoke rule engine and not
  Semgrep -- decided in the office-hours design session because the control-ID-native
  Rego policy format fits the HIPAA/SOC2 control-mapping story directly, and because
  the hosted-tier roadmap already commits to evaluating live API/runtime state (not
  just static config), which the same Rego policies extend to without a rewrite.
  Policies live in `internal/policy/rego/*.rego`, loaded via `//go:embed` and prepared
  once at startup (`rego.New(...).PrepareForEval(ctx)`) per OPA's own documented
  performance pattern -- never re-parsed per scan.
- **SARIF export:** `github.com/owenrumney/go-sarif/v3` -- a maintained SARIF 2.1.0
  library, reused instead of hand-rolling the schema.
- **License:** Apache 2.0 (core scanner, rule packs, SARIF output, control-mapping
  metadata) + proprietary (hosted continuous-monitoring, signed audit trail,
  compliance-report export, second-vertical SOC2 mapping -- none of this exists yet)
- **Repo goal:** Become the reference tenant-isolation audit tool for self-hosted
  multi-agent deployments, proven first against goclaw's five confirmed open security
  issues, then niched into a healthcare/HIPAA-first vertical GTM -- NOT a horizontal
  governance-platform competitor to Arcade.dev/Zenity.

## Git Workflow

When asked to commit, push, or "update GitHub" -- just do it. No questions.

- `git add` relevant files -> `git commit` -> `git push origin main` in one shot
- Every commit message ends with:
  Built by Rudrendu Paul, developed with Claude Code
- Never use `Co-Authored-By:` lines.

## Engineering Standards (block all tasks until these pass)

1. **Lint:** `golangci-lint run ./...` -- zero issues
2. **Vet/build:** `go vet ./... && go build ./...` -- zero errors
3. **Tests:** `go test ./... -cover` -- 80% minimum overall; every TA0N rule must have
   both a labeled `vulnerable` and `clean` fixture under
   `internal/policy/testdata/ta0N/{vulnerable,clean}/` proving true-positive and
   true-negative behavior, since a false negative there is a missed security finding
4. **Security:** `govulncheck ./...` -- no vulnerabilities affecting code this binary
   actually calls
5. **SARIF validity:** any change to `internal/report/sarif.go` or the rule pack must
   re-run the SARIF schema validation (see the integration test in
   `cmd/tenantguard/integration_test.go`) -- a SARIF change that "parses as JSON" is
   not sufficient, it must validate against the real SARIF 2.1.0 schema

Do NOT mark a task complete if any of these fail. Fix the root cause. Do not suppress
errors or add `//nolint` without a comment explaining why.

## Planning Rules

Enter plan mode for any task that:
- Touches more than 2 files
- Adds or changes a rule in `internal/policy/rego/`
- Changes the `CollectedConfig` / `regoInput` shape (the merged-document input every
  Rego policy evaluates against)
- Changes the HIPAA/SOC2 control-mapping logic in `internal/compliance/`
- Changes the SARIF export schema

Write the plan before touching code. If something goes wrong mid-task, stop and re-plan.

## Anti-Sycophancy Rules

These override default behavior in every session:

1. **No detection-rate or false-positive-rate claim without a labeled fixture run.**
   Before stating either number, run `go test ./internal/policy/... -v` against the
   `vulnerable`/`clean` fixture pairs and show the command output.
2. **Every FAIL finding must cite the exact config location and, where applicable,
   the goclaw issue it maps to.** A finding that cannot point to a specific file:line
   is not shippable.
3. **Never overstate the HIPAA/SOC2 control mapping's authority.** The mapping in
   `internal/compliance/hipaa.go` is TenantGuard's own interpretation -- it is not
   legal advice and has not been reviewed by a licensed compliance attorney or
   healthcare-compliance consultant. Every `Finding.Provisional` field and every
   report's language must reflect this. Do not remove the "provisional" framing
   anywhere it appears without a documented third-party review first.
4. **Comparison claims require specificity.** Any comparison to Arcade.dev, Zenity,
   or a hypothetical hyperscaler-native tool must specify exactly what TenantGuard
   does differently (vertical-specific control mapping, self-hostable/air-gapped-
   first, narrow scope by design). "We do security auditing too" is not enough.
5. **Compliance-officer skepticism check.** Before merging any new HIPAA/SOC2 control
   mapping, ask: "would a real health-tech compliance officer find this citation
   accurate and specific, or would they flag it as generic boilerplate?" If the
   honest answer is "generic," do not merge until it is reviewed against the actual
   regulation text.
6. **Never claim a clean scan means "compliant" or "safe."** A PASS means the
   deployment was evaluated against the current rule set and no match was found --
   it is not a certification of HIPAA compliance or of general security.

## What Claude Must Never Do

- Claim a detection or false-positive number without a fixture-test command output
- Ship a new rule without a labeled `vulnerable` fixture and labeled `clean` fixture
- Commit with `--no-verify`
- Merge a PR that regresses test coverage below 80% overall (or below full
  true-positive/true-negative coverage on any TA0N rule) without explicit written
  approval
- State that a clean scan means a deployment is "HIPAA compliant" or "secure" --
  only that it passed the current rule set
- Present the HIPAA/SOC2 control mapping as legally reviewed unless it actually has
  been

## Key Files

| File | Purpose |
|---|---|
| `cmd/tenantguard/main.go` | CLI entry point -- `scan`, `--target`, `--demo`, `--format`, `--control`, `--sarif-out` flags; exit codes 0/1/2 |
| `internal/collector/config.go` | Walks a target directory, merges every `*.yml`/`*.yaml` into one `CollectedConfig`, fails loudly on malformed input |
| `internal/collector/lineindex.go` | Resolves exact source line numbers for every collected entry, so findings cite `file:line` |
| `internal/policy/rego/ta01.rego` .. `ta05.rego` | The five tenant-isolation rules, each mapped 1:1 to a confirmed `goclaw` issue |
| `internal/policy/policy.go` | Embeds and prepares the Rego policies, evaluates them against a `CollectedConfig`, converts results to `[]Finding` |
| `internal/policy/testdata/ta0N/{vulnerable,clean}/` | Labeled fixtures per rule -- source of every detection-rate claim |
| `internal/compliance/hipaa.go` | HIPAA Sec164.312 control-mapping metadata (provisional, v0.1 only) |
| `internal/report/sarif.go` | SARIF 2.1.0 export via `owenrumney/go-sarif` |
| `internal/report/terminal.go` | Human-readable terminal output |
| `internal/demo/` | Bundled synthetic deployment for `tenantguard scan --demo` (zero-setup TTHW path) |
| `action/action.yml` | GitHub Action wrapper for CI-triggered scans |
| `.github/workflows/ci.yml` | lint -> vet -> test -> govulncheck |
| `.github/workflows/release.yml` | GoReleaser on tag push -- cross-platform binaries, sigstore signing, SBOM |
| `CONTRIBUTING.md` | Read before any contributor-facing change |
| `SECURITY.md` | CVE disclosure policy |
| `CHANGELOG.md` | Updated on every PR that changes public behavior |

## Session Start Checklist

1. Run `git status` and `git log --oneline -5` to understand current state
2. Run `go test ./... -cover` to confirm baseline is green before touching anything
3. Read `CHANGELOG.md` last entry to understand what changed recently
4. If a bug is reported: write a failing labeled fixture (vulnerable or clean,
   matching the rule category) that reproduces it first, then fix the rule
5. Check: have any of goclaw's five founding issues (#1163, #1070, #1217, #1227,
   #1216) been closed or fixed upstream? Has Arcade.dev, Zenity, or a hyperscaler
   shipped a comparable vertical-mapped feature? If yes, check whether the rule pack
   or the differentiation framing needs updating.
