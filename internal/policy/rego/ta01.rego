# TA01 — Sandbox/Workspace Mount Isolation
# Maps to goclaw#1163: a sandbox mount path that isn't scoped per tenant risks
# one tenant's workspace being visible to another. A mount is compliant if
# EITHER its path carries the ${TENANT_ID} scoping placeholder convention OR
# scoped_per_tenant is explicitly declared true — a second, independent
# signal for deployments where the mount path is computed by real code (a Go
# collector's resolved path will never contain that literal template token)
# and the scoping guarantee is instead attested directly.
package tenantguard.ta01

import rego.v1

violations contains i if {
	some i
	mount := input.sandboxes[i]
	not contains(mount.path, "${TENANT_ID}")
	not mount.scoped_per_tenant
}
