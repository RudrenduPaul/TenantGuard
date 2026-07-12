package report

import (
	"fmt"
	"io"

	"github.com/RudrenduPaul/TenantGuard/internal/policy"
)

// WriteTerminal renders findings as human-readable text to w, plus a summary
// line. It always prints every rule's PASS/FAIL, not just failures, so a
// clean scan is visibly "5 checked, 0 failed" rather than silent. Write
// errors to a terminal/CI log are not actionable (there's nothing sensible to
// do if stdout itself fails) and are deliberately discarded, matching
// standard practice for CLI terminal output.
func WriteTerminal(w io.Writer, target string, findings []policy.Finding) {
	_, _ = fmt.Fprintf(w, "TenantGuard: Tenant-Isolation Audit\n")
	_, _ = fmt.Fprintf(w, "Target: %s\n\n", target)

	failCount, passCount := 0, 0
	for _, f := range findings {
		if f.Status == policy.StatusFail {
			failCount++
			_, _ = fmt.Fprintf(w, "[FAIL]  %s %s\n", f.RuleID, f.Description)
			_, _ = fmt.Fprintf(w, "  %s\n", f.Location.String())
			line := fmt.Sprintf("  Maps to: %s", valueOrDash(f.MapsToIssue))
			if f.HIPAACitation != "" {
				line += fmt.Sprintf(" | %s (provisional)", f.HIPAACitation)
			}
			_, _ = fmt.Fprintln(w, line)
			_, _ = fmt.Fprintln(w)
		} else {
			passCount++
		}
	}

	if passCount > 0 {
		_, _ = fmt.Fprintf(w, "[PASS]  %d check(s) clear\n\n", passCount)
	}

	_, _ = fmt.Fprintf(w, "Summary: %d FAIL, %d PASS\n", failCount, passCount)
	if failCount > 0 {
		_, _ = fmt.Fprintln(w, "Findings map to confirmed open goclaw issues where applicable. HIPAA citations are provisional, see README.")
	}
}

func valueOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
