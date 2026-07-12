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
		description: "sandbox/workspace mount path is not scoped per-tenant (no ${TENANT_ID} placeholder and no explicit scoped_per_tenant declaration)",
		mapsToIssue: "goclaw#1163",
	},
	"TA02": {
		id:          "TA02",
		description: "MCP tool URL targets a private/loopback/reserved address (via real CIDR containment on a literal or DNS-resolved IP) without a verified, IP-pinned SSRF validator or an explicit host allowlist entry. CAVEAT: a PASS trusts the deployment's own pins_resolved_ip/validates_private declaration -- TenantGuard cannot verify the real validator actually pins the resolved IP for the connection itself, so DNS-rebinding/TOCTOU risk persists if that declaration is inaccurate",
		mapsToIssue: "goclaw#1070",
	},
	"TA03": {
		id:          "TA03",
		description: "cron binding's target agent does not belong to the declaring tenant",
		mapsToIssue: "goclaw#1217",
	},
	"TA04": {
		id:          "TA04",
		description: "exec tool denies direct env dump but not indirect env reads (e.g. jq $ENV), or allows credential-chain leakage via allow_chain_exec (goclaw#1033)",
		mapsToIssue: "goclaw#1227",
	},
	"TA05": {
		id:          "TA05",
		description: "exec-approval allow-always entry is keyed on basename only, not a full path scope",
		mapsToIssue: "goclaw#1216",
	},
	"TA08": {
		id:          "TA08",
		description: "provider's OAuth/credential token storage does not declare a recognized strong encryption-at-rest algorithm",
		mapsToIssue: "goclaw#65",
	},
	"TA09": {
		id:          "TA09",
		description: "sandbox fail-closed posture not declared (sandbox.on_unavailable must be \"fail_closed\")",
		mapsToIssue: "goclaw#246",
	},
	"TA10": {
		id:          "TA10",
		description: "agent does not explicitly declare a per-agent config override (workspace restriction or sandbox config), risking silent inheritance of an undeclared global default",
		mapsToIssue: "goclaw#145",
	},
	"TA12": {
		id:          "TA12",
		description: "deployment does not guarantee owner/sysadmin recovery access (no owner_ids declared and/or no recovery command declared)",
		mapsToIssue: "goclaw#954",
	},
	"TA13": {
		id:          "TA13",
		description: "MCP/CLI bridge does not declare HMAC-signed context headers (bridge.hmac_enabled and bridge.context_headers_signed)",
		mapsToIssue: "goclaw#91",
	},
	"TA14": {
		id:          "TA14",
		description: "browser/container profile storage path is not scoped per-agent/per-tenant",
		mapsToIssue: "goclaw#778",
	},
	"TA06": {
		id:          "TA06",
		description: "cron binding does not declare that its store layer captures/replays the human creator's sender identity at fire time",
		mapsToIssue: "goclaw#1129",
	},
	"TA07": {
		id:          "TA07",
		description: "sandbox container privilege is not hardened (root user by default, full host-env passthrough, tmpfs missing noexec/nosuid/nodev, or a dangerous Linux capability added)",
		mapsToIssue: "goclaw#1014",
	},
	"TA11": {
		id:          "TA11",
		description: "channel/session device identity is shared across channel_instances declaring different tenants",
		mapsToIssue: "goclaw#1064",
	},
}
