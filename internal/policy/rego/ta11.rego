# TA11 — Channel/Session Cross-Tenant Identity Sharing
# Maps to goclaw#1064/#1065: multiple WhatsApp channel_instances shared one
# whatsmeow device row (container.GetFirstDevice(ctx) on one shared
# sqlstore.Container), so every instance connected as the same already-paired
# WhatsApp account regardless of which tenant or agent it was wired to. A
# channel_instances entry is a fail-closed violation whenever its
# device_session_id matches another entry's device_session_id but the two
# declare different tenants — that shared session row is exactly the
# identity-bleed goclaw#1064 describes.
package tenantguard.ta11

import rego.v1

violations contains i if {
	some i, j
	i != j
	a := input.channel_instances[i]
	b := input.channel_instances[j]
	a.device_session_id == b.device_session_id
	a.tenant != b.tenant
}
