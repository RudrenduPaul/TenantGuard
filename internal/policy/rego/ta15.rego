# TA15 — Channel Instance Reload Blast Radius
# Maps to goclaw#1147: InstanceLoader.Reload() does a destructive full
# stop/restart of every running channel_instance on any single
# channel_instance create/update/delete, because the reload event carries no
# information about which instance actually changed and there is no
# fingerprint/diff step. One tenant's channel create/update/delete therefore
# interrupts every other tenant's in-progress conversations across every
# channel -- a cross-tenant availability blast radius, not just an identity
# leak (that's TA11's concern). A channel_instances entry is a fail-closed
# violation unless it explicitly declares reload_strategy: "differential" --
# an undeclared value, an empty string, or an explicit "full" all default to
# the destructive full-restart behavior this rule flags, matching this
# collector's fail-loudly philosophy (see collector.Collect's doc comment).
package tenantguard.ta15

import rego.v1

violations contains i if {
	some i
	input.channel_instances[i].reload_strategy != "differential"
}
