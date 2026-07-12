# TA09 — Sandbox Fail-Closed Posture Declaration
# Maps to goclaw#246: when the Docker sandbox is unavailable at runtime
# (daemon down, binary missing), goclaw's exec path used to silently fall
# back to unsandboxed host execution. PR #246 hardened the runtime to return
# an error instead of running the tool call outside the sandbox.
#
# This rule checks the same posture at the config-declaration level: a
# deployment must explicitly declare sandbox.on_unavailable: "fail_closed".
# An undeclared value is treated as a violation, not a silent pass — an
# operator who never wrote this key has no configured fail-closed behavior
# at all, which is exactly the gap goclaw#246 fixed in code. This does not
# inspect the actual Go runtime fallback path itself; it only checks whether
# the deployment's static config declares the safe posture.
package tenantguard.ta09

import rego.v1

safe_value := "fail_closed"

violations contains 0 if {
	not input.sandbox_on_unavailable_declared
}

violations contains 0 if {
	input.sandbox_on_unavailable_declared
	input.sandbox_on_unavailable != safe_value
}
