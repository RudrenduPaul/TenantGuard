# TA12 — Owner/Sysadmin Recovery Guarantee
# Maps to goclaw#954, a maintainer-acknowledged CRITICAL design gap: nothing
# guarantees a valid gateway-token-authenticated `system` account is always
# treated as emergency sysadmin, and nothing guarantees a recovery/reset
# command exists — together these risk permanent operator lockout if the
# owner configuration is ever wrong.
#
# Unlike TA01-TA05, this is a deployment-level check, not a per-array-entry
# check: there is no list of "owners" to walk, so `violations` is a set that
# is either empty (PASS) or contains a sentinel index 0 (FAIL). Go-side,
# internal/policy/policy.go's buildTA12Findings only checks whether this set
# is empty, not what it contains — the sentinel value itself carries no
# meaning beyond "at least one condition below fired."
package tenantguard.ta12

import rego.v1

# No owner_ids declared means no account is guaranteed to be treated as
# emergency sysadmin.
violations contains 0 if {
	count(input.owner_ids) == 0
}

# No declared recovery command means there is no way to regain sysadmin
# access if the owner configuration is ever wrong.
violations contains 0 if {
	not input.has_recovery_command
}
