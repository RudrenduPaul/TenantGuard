# TA14 — Per-Agent Resource (Browser/Container Profile) Isolation
# Maps to nextlevelbuilder/goclaw#778: goclaw's own "cross-agent browser
# profile isolation fix" shipped as part of a larger browser-automation
# feature, confirming that unscoped browser/container profile storage paths
# are a genuine cross-tenant isolation defect. A compliant profile path must
# contain the ${TENANT_ID} scoping placeholder, the same convention TA01
# applies to sandbox workspace mounts; a shared/static profile root does not.
#
# A second, deployment-level check (also mapped here, under the same rule
# ID) closes a related gap surfaced by nextlevelbuilder/goclaw#1028's
# Lightpanda backend: a backend whose isolation guarantee is architectural
# (e.g. "a fresh browser per CDP connection") rather than path-based
# declares zero resources.browser.profiles entries. Before
# browser_isolation_mode existed, that meant the check above had nothing to
# iterate and silently produced zero violations -- not because isolation had
# been verified, but because there was no declared fact to check at all. A
# deployment that declares a browser backend is now obligated to also
# declare backend_isolation_mode ("scoped_path" or "stateless"); leaving it
# undeclared is itself a violation instead of a silent pass-by-omission.
package tenantguard.ta14

import rego.v1

# Per-profile path scoping. Skipped when the deployment has explicitly
# declared "stateless" isolation -- that mode's whole claim is that no
# persistent, scannable path is the isolation mechanism, so judging its
# (likely absent, or purely incidental) profile paths against the
# ${TENANT_ID} convention would be evaluating the wrong thing.
violations contains i if {
	some i
	profile := input.resource_profiles[i]
	input.browser_isolation_mode != "stateless"
	not contains(profile.path, "${TENANT_ID}")
}

# Deployment-level: a declared browser backend obligates a declared
# isolation-mode posture. The sentinel key (count of resource_profiles) is
# out of range for any real per-profile index, so it can never collide with
# the per-index violations above while still fitting the same flat
# int-keyed violations set the Go side (extractViolations) already expects.
violations contains n if {
	n := count(input.resource_profiles)
	input.browser_backend_declared
	not input.browser_isolation_mode_declared
}

# Deployment-level: an isolation mode was declared, but it's neither of the
# two TenantGuard recognizes. An unrecognized value (e.g. a typo) must FAIL
# loudly rather than silently be treated as an implicit "stateless" skip.
violations contains n if {
	n := count(input.resource_profiles)
	input.browser_isolation_mode_declared
	not input.browser_isolation_mode == "stateless"
	not input.browser_isolation_mode == "scoped_path"
}
