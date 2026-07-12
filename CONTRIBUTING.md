# Contributing to TenantGuard

Thanks for considering a contribution. This project is young and the areas below are
the highest-leverage places to help.

## Adding a new rule

Every rule lives in `internal/policy/rego/ta0N.rego` and needs:

1. A Rego policy under `package tenantguard.ta0N` exposing a `violations` set.
2. An entry in `ruleMetadata` in `internal/policy/finding.go` (description, and the
   upstream issue it maps to, if any).
3. A labeled fixture pair: `internal/policy/testdata/ta0N/vulnerable/deployment.yaml`
   (should FAIL) and `internal/policy/testdata/ta0N/clean/deployment.yaml` (should
   PASS).
4. A test in `internal/policy/policy_test.go` asserting both directions.
5. If the rule should carry a HIPAA citation, add it to `hipaaCitations` in
   `internal/compliance/hipaa.go` — and be honest about whether it's a real fit, not
   generic boilerplate — an unsupported compliance claim is worse than no claim at all.

No rule ships without both fixtures. A rule with only a `vulnerable` fixture has an
unverified false-positive rate; a rule with only a `clean` fixture has an unverified
detection rate.

## Reporting a tenant-isolation defect we missed

If you find a real tenant-isolation gap in `goclaw` or a comparable self-hosted
multi-tenant agent platform that TenantGuard doesn't catch, please open a GitHub
Discussion with:
- The exact config pattern that reproduces it
- Which platform and version you found it in
- Whether it's already been reported upstream to that platform's own maintainers

We want the rule pack to grow from real deployments, not just our own fixture set.

## Development setup

```bash
git clone https://github.com/RudrenduPaul/TenantGuard.git
cd TenantGuard
go build ./...
go test ./... -cover
```

Requires Go 1.26+. No other runtime dependencies — OPA and the SARIF library are
embedded as Go modules, not external tools you need to install separately.

## Before opening a PR

```bash
golangci-lint run ./...
go vet ./...
go test ./... -cover
govulncheck ./...
```

All four must be clean before a PR is opened — lint, vet, tests, and vulnerability
scanning are this repo's non-negotiable baseline, not optional extras.

## Code of conduct

Be direct, be kind, assume good faith. Disagreements about rule accuracy or HIPAA
citation wording are welcome and expected — get it right, not just merged.
