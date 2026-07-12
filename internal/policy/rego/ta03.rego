# TA03 — Cross-Agent Authorization Boundary
# Maps to goclaw#1217: a cron binding must target an agent belonging to the
# same tenant that declared the binding. A dangling reference (no matching
# agent at all) or a cross-tenant reference are both fail-closed violations —
# an unresolvable reference is exactly the authorization-boundary gap this
# rule exists to catch, not a case to skip past.
package tenantguard.ta03

import rego.v1

violations contains i if {
	some i
	binding := input.cron_schedules[i]
	not agent_in_tenant(binding.target_agent, binding.tenant)
}

agent_in_tenant(agent_name, tenant) if {
	some a in input.agents
	a.name == agent_name
	a.tenant == tenant
}
