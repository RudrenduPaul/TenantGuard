# TA13 — MCP/CLI Bridge Context Integrity (HMAC-Signed Headers)
# Maps to goclaw#91: the MCP/CLI bridge must sign per-session context headers
# (X-Bridge-Sig, verified via SignBridgeContext/VerifyBridgeContext) so a
# forged X-Agent-ID/X-User-ID/X-Channel header can't impersonate another
# tenant's session through the bridge. A deployment that never declares
# bridge.hmac_enabled and bridge.context_headers_signed defaults to
# unsigned, and is flagged exactly like one that explicitly disables them —
# see collector.Collect's doc comment: a missing declaration must fail
# loudly, never scan clean by default.
package tenantguard.ta13

import rego.v1

# TA13 is deployment-level, not per-entry — there is exactly one bridge
# section per scan, so every violation is keyed on index 0. Rego set
# semantics dedupe automatically if both rules fire for the same scan.
violations contains 0 if {
	not input.bridge_hmac_enabled
}

violations contains 0 if {
	not input.bridge_context_headers_signed
}
