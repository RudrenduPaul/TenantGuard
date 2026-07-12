# TA01 — Sandbox/Workspace Mount Isolation
# Maps to goclaw#1163: a sandbox mount path that isn't scoped per tenant risks
# one tenant's workspace being visible to another. A compliant mount path must
# contain the ${TENANT_ID} scoping placeholder; a shared/static root does not.
package tenantguard.ta01

import rego.v1

violations contains i if {
	some i
	mount := input.sandboxes[i]
	not contains(mount.path, "${TENANT_ID}")
}
