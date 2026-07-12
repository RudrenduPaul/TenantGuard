# TA07 — Sandbox Container-Privilege Hardening
# Merges two independently self-diagnosed-and-fixed goclaw gaps that both
# trace to the same missing-capability class in the sandbox schema:
#   - goclaw#1014 / goclaw#1015: Docker defaulted to running as root, and
#     bwrap inherited the full host environment (credential/PATH leak).
#   - goclaw#728 / goclaw#524: tmpfs mounts missing noexec/nosuid/nodev, and
#     cap_add including unneeded SETUID/SETGID/CHOWN (privilege escalation).
# A sandbox mount fails TA07 if it runs as root by default, passes through
# the full host environment, mounts tmpfs without the safe flag set, or adds
# a dangerous Linux capability.
package tenantguard.ta07

import rego.v1

# safe_tmpfs_flags is the minimal flag set every tmpfs mount must carry to
# stop it being used to bypass exec/setuid controls.
safe_tmpfs_flags := {"noexec", "nosuid", "nodev"}

# dangerous_caps lists Linux capabilities that let a sandboxed process
# escalate privilege or interfere with host/other-tenant state if added.
dangerous_caps := {"SETUID", "SETGID", "CHOWN", "SYS_ADMIN", "DAC_OVERRIDE", "NET_ADMIN", "SYS_PTRACE"}

# Reason 1: sandbox runs as root by default (goclaw#1014, goclaw#1015).
violations contains i if {
	some i
	mount := input.sandboxes[i]
	mount.user in {"", "root"}
}

# Reason 2: sandbox inherits the full host environment (goclaw#1014, goclaw#1015).
violations contains i if {
	some i
	mount := input.sandboxes[i]
	mount.env_mode == "inherit_host"
}

# Reason 3: tmpfs mount is missing noexec, nosuid, or nodev (goclaw#728).
violations contains i if {
	some i
	mount := input.sandboxes[i]
	declared := {f | some f in mount.tmpfs_flags}
	missing := safe_tmpfs_flags - declared
	count(missing) > 0
}

# Reason 4: cap_add includes a dangerous capability (goclaw#524).
violations contains i if {
	some i
	mount := input.sandboxes[i]
	some cap in mount.cap_add
	cap in dangerous_caps
}
