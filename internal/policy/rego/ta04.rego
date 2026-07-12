# TA04 — Secret/Env Leakage via Exec Tools
# Maps to goclaw#1227: an exec tool that denies direct env-dump reads but does
# not also deny indirect reads (e.g. a shell invocation of `jq $ENV`) still
# leaks secrets through the uncovered path.
package tenantguard.ta04

import rego.v1

violations contains i if {
	some i
	tool := input.exec_tools[i]
	tool.env_policy.deny_direct_env_dump
	not tool.env_policy.deny_indirect_env_read
}
