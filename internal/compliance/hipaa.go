// Package compliance attaches regulatory-control citation metadata to scan
// findings. In v0.1 this is HIPAA Security Rule Sec164.312 only, and every
// citation is marked provisional/unverified: it is TenantGuard's own
// interpretation of which technical safeguard a finding relates to, not
// legal advice, and has not been reviewed by a licensed compliance attorney
// or healthcare-compliance consultant. See
// tenantguard-office-hours-design-2026-07-11.md, Dependencies section, for
// the plan to get this reviewed before any hosted-tier compliance-report
// claim ships.
package compliance

import "github.com/RudrenduPaul/TenantGuard/internal/policy"

// hipaaCitations maps each TA0N rule to the HIPAA Security Rule technical
// safeguard it most directly relates to. This mapping is TenantGuard's own
// interpretation — see the package doc comment above.
var hipaaCitations = map[string]string{
	"TA01": "HIPAA Sec164.312(a)(1) Access Control",
	"TA02": "HIPAA Sec164.312(e)(1) Transmission Security",
	"TA03": "HIPAA Sec164.312(a)(1) Access Control",
	"TA04": "HIPAA Sec164.312(a)(2)(iv) Encryption/Decryption",
	"TA05": "HIPAA Sec164.312(a)(1) Access Control",
	"TA11": "HIPAA Sec164.312(a)(1) Access Control",
}

// Annotate attaches a provisional HIPAA citation to every FAIL finding in
// place. PASS findings are left uncited — there is nothing to report a
// citation against.
func Annotate(findings []policy.Finding) {
	for i := range findings {
		if findings[i].Status != policy.StatusFail {
			continue
		}
		if citation, ok := hipaaCitations[findings[i].RuleID]; ok {
			findings[i].HIPAACitation = citation
			findings[i].Provisional = true
		}
	}
}
