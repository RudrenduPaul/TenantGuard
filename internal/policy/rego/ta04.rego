# TA04 — Secret/Env Leakage via Exec Tools
# Maps to goclaw#1227: an exec tool that denies direct env-dump reads but does
# not also deny indirect reads (e.g. a shell invocation of `jq $ENV`) still
# leaks secrets through the uncovered path.
#
# Also maps to goclaw#1033: an exec tool with allow_chain_exec: true injects
# its credential env vars into every command of a shell operator chain (e.g.
# `which gh && gh pr list`), not just the credentialed binary itself, making
# those secrets visible to whatever else rides along in the chain. This is a
# real, distinct credential-leakage-via-exec-tool pattern, not a variant of
# the direct/indirect-dump gap above — so it is flagged unconditionally
# whenever allow_chain_exec is set, regardless of the env-dump denylist
# settings, since PR#1033 documents no other declared field that mitigates it.
package tenantguard.ta04

import rego.v1

violations contains i if {
	some i
	tool := input.exec_tools[i]
	tool.env_policy.deny_direct_env_dump
	not tool.env_policy.deny_indirect_env_read
}

violations contains i if {
	some i
	tool := input.exec_tools[i]
	tool.env_policy.allow_chain_exec
}
