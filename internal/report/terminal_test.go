package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/RudrenduPaul/TenantGuard/internal/collector"
	"github.com/RudrenduPaul/TenantGuard/internal/policy"
	"github.com/RudrenduPaul/TenantGuard/internal/report"
)

func TestWriteTerminalReportsFailAndPass(t *testing.T) {
	findings := []policy.Finding{
		{RuleID: "TA01", Status: policy.StatusFail, Location: collector.Location{File: "a.yaml", Line: 3}, Description: "no tenant scoping", MapsToIssue: "goclaw#1163", HIPAACitation: "HIPAA Sec164.312(a)(1)"},
		{RuleID: "TA02", Status: policy.StatusPass},
	}
	var buf bytes.Buffer
	report.WriteTerminal(&buf, "/some/target", findings)

	out := buf.String()
	for _, want := range []string{"/some/target", "[FAIL]", "a.yaml:3", "goclaw#1163", "HIPAA Sec164.312(a)(1)", "provisional", "1 FAIL, 1 PASS"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestWriteTerminalCleanScan(t *testing.T) {
	findings := []policy.Finding{
		{RuleID: "TA01", Status: policy.StatusPass},
		{RuleID: "TA02", Status: policy.StatusPass},
	}
	var buf bytes.Buffer
	report.WriteTerminal(&buf, "/some/target", findings)

	out := buf.String()
	if strings.Contains(out, "[FAIL]") {
		t.Errorf("clean scan should have no [FAIL] markers, got:\n%s", out)
	}
	if !strings.Contains(out, "0 FAIL, 2 PASS") {
		t.Errorf("expected summary '0 FAIL, 2 PASS', got:\n%s", out)
	}
}
