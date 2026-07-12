# TA14 — Per-Agent Resource (Browser/Container Profile) Isolation
# Maps to nextlevelbuilder/goclaw#778: goclaw's own "cross-agent browser
# profile isolation fix" shipped as part of a larger browser-automation
# feature, confirming that unscoped browser/container profile storage paths
# are a genuine cross-tenant isolation defect. A compliant profile path must
# contain the ${TENANT_ID} scoping placeholder, the same convention TA01
# applies to sandbox workspace mounts; a shared/static profile root does not.
package tenantguard.ta14

import rego.v1

violations contains i if {
	some i
	profile := input.resource_profiles[i]
	not contains(profile.path, "${TENANT_ID}")
}
