package compliance_test

import (
	"testing"

	"github.com/RudrenduPaul/TenantGuard/internal/compliance"
	"github.com/RudrenduPaul/TenantGuard/internal/policy"
)

func TestAnnotateOnlyCitesFailFindings(t *testing.T) {
	findings := []policy.Finding{
		{RuleID: "TA01", Status: policy.StatusPass},
		{RuleID: "TA01", Status: policy.StatusFail},
	}
	compliance.Annotate(findings)

	if findings[0].HIPAACitation != "" {
		t.Errorf("PASS finding should not get a HIPAA citation, got %q", findings[0].HIPAACitation)
	}
	if findings[1].HIPAACitation == "" {
		t.Error("FAIL finding for a known rule should get a HIPAA citation")
	}
	if !findings[1].Provisional {
		t.Error("every HIPAA citation must be marked provisional in v0.1 — it is TenantGuard's own interpretation, not legal advice")
	}
}

func TestAnnotateUnknownRuleGetsNoCitation(t *testing.T) {
	findings := []policy.Finding{
		{RuleID: "TA99", Status: policy.StatusFail},
	}
	compliance.Annotate(findings)
	if findings[0].HIPAACitation != "" {
		t.Errorf("an unrecognized rule ID should not get a fabricated citation, got %q", findings[0].HIPAACitation)
	}
}

func TestAllFiveRulesHaveACitation(t *testing.T) {
	for _, rule := range []string{"TA01", "TA02", "TA03", "TA04", "TA05", "TA06"} {
		findings := []policy.Finding{{RuleID: rule, Status: policy.StatusFail}}
		compliance.Annotate(findings)
		if findings[0].HIPAACitation == "" {
			t.Errorf("%s should have a HIPAA citation mapped", rule)
		}
	}
}
