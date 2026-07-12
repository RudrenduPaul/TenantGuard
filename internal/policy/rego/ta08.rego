# TA08 — Credential/OAuth Token Storage Encryption Declaration
# Maps to goclaw#65: that PR introduces AES-256-GCM-encrypted OAuth token
# storage as the good example (PKCE flow + local callback server + encrypted
# token storage with auto-refresh). A provider config that omits an explicit
# strong-encryption declaration for its stored OAuth/credential tokens — or
# declares something other than a recognized strong-encryption algorithm —
# is a static-config-level signal that stored credentials may not be
# encrypted at rest.
package tenantguard.ta08

import rego.v1

strong_encryption_algorithms := {"aes-256-gcm"}

violations contains i if {
	some i
	provider := input.providers[i]
	not strong_encryption_algorithms[lower(provider.oauth_token_storage_encryption)]
}
