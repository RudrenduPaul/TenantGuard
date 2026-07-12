# TA10 — Per-Agent Config-Override Declaration Completeness (best-effort)
# Maps to goclaw#145 (merged): per-agent DB settings (workspace restriction,
# sandbox config, among others) were silently ignored at runtime because tool
# config was baked in at process startup instead of resolved per-agent. This
# rule cannot see that Go-level context-propagation bug from static YAML —
# it only checks whether the config layer itself declares an explicit
# per-agent override for these settings, or silently relies on an undeclared
# global default. A best-effort proxy, not a runtime check.
package tenantguard.ta10

import rego.v1

violations contains i if {
	some i
	agent := input.agents[i]
	not agent.has_workspace_restriction_override
}

violations contains i if {
	some i
	agent := input.agents[i]
	not agent.has_sandbox_config_override
}
