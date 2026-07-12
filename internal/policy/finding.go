// Package policy embeds Open Policy Agent (github.com/open-policy-agent/opa/v1/rego)
// as a library — not a subprocess, not a hosted control plane — to evaluate
// the TA01-TA05 and TA13 tenant-isolation rules against a collector.CollectedConfig.
// Rego was chosen over a bespoke rule engine specifically because its
// control-ID-native policy format is a direct fit for the HIPAA/SOC2
// control-mapping story (see tenantguard-office-hours-design-2026-07-11.md,
// Approach C), and it stays embeddable as a single static binary.
package policy

import "github.com/RudrenduPaul/TenantGuard/internal/collector"

// Finding is one rule evaluation result. Status is "FAIL" or "PASS" — a rule
// that never ran at all (policy load failure) is not represented as a
// Finding; see Evaluator.Rules() for that distinction.
type Finding struct {
	RuleID        string
	Status        string
	Location      collector.Location
	Description   string
	MapsToIssue   string
	HIPAACitation string
	Provisional   bool
}

const (
	StatusFail = "FAIL"
	StatusPass = "PASS"
)

// ruleMeta is the static, non-input-dependent description of one TA0N rule —
// what it maps to and how to describe a violation.
type ruleMeta struct {
	id          string
	description string
	mapsToIssue string
}

var ruleMetadata = map[string]ruleMeta{
	"TA01": {
		id:          "TA01",
		description: "sandbox/workspace mount path is not scoped per-tenant",
		mapsToIssue: "goclaw#1163",
	},
	"TA02": {
		id:          "TA02",
		description: "MCP tool URL targets a private/loopback address without declared SSRF validation",
		mapsToIssue: "goclaw#1070",
	},
	"TA03": {
		id:          "TA03",
		description: "cron binding's target agent does not belong to the declaring tenant",
		mapsToIssue: "goclaw#1217",
	},
	"TA04": {
		id:          "TA04",
		description: "exec tool denies direct env dump but not indirect env reads (e.g. jq $ENV)",
		mapsToIssue: "goclaw#1227",
	},
	"TA05": {
		id:          "TA05",
		description: "exec-approval allow-always entry is keyed on basename only, not a full path scope",
		mapsToIssue: "goclaw#1216",
	},
	"TA13": {
		id:          "TA13",
		description: "MCP/CLI bridge does not declare HMAC-signed context headers (bridge.hmac_enabled and bridge.context_headers_signed)",
		mapsToIssue: "goclaw#91",
	},
}
