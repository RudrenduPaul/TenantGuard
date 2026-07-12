# TA05 — Exec-Approval Bypass / Path-Scoping
# Maps to goclaw#1216: an "allow-always" approval keyed on basename alone can
# be reused against a different, path-scoped executable sharing that
# basename. A compliant approval must be scoped to a specific full path.
package tenantguard.ta05

import rego.v1

# Each violation names both the owning exec tool and the specific approval
# entry within it, since approvals are nested one level deeper than the
# other four rules' flat lists.
violations contains {"exec_index": ei, "approval_index": ai} if {
	some ei
	tool := input.exec_tools[ei]
	some ai
	approval := tool.approvals[ai]
	not approval.path_scoped
}
