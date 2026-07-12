# TA06 — Cron Creator Identity Capture
# Maps to goclaw#1129: cron jobs created in a group context lost the human
# creator's sender/role identity entirely at fire time (the store layer
# stamped the job with only the group UserID, never a real SenderID), so a
# legitimate group-context mutation (e.g. write_file) at fire time got
# attributed to "system context" and denied. The fix captures the creator's
# sender/role at cron-create time and replays it at every fire. A cron
# binding whose config doesn't declare that its store layer captures/replays
# creator identity at fire time reproduces the same gap and is a fail-closed
# violation.
package tenantguard.ta06

import rego.v1

violations contains i if {
	some i
	binding := input.cron_schedules[i]
	not binding.captures_creator_identity
}
