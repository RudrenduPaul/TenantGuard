package report_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/RudrenduPaul/TenantGuard/internal/collector"
	"github.com/RudrenduPaul/TenantGuard/internal/policy"
	"github.com/RudrenduPaul/TenantGuard/internal/report"
)

func TestEmptyFindingsProducesValidSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, nil); err != nil {
		t.Fatalf("WriteSARIF with no findings should not error: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	runs, ok := doc["runs"].([]interface{})
	if !ok || len(runs) != 1 {
		t.Fatalf("expected exactly 1 run, got %v", doc["runs"])
	}
	run := runs[0].(map[string]interface{})
	results, ok := run["results"].([]interface{})
	if !ok {
		t.Fatalf("expected results to be present (even if empty), got %v", run["results"])
	}
	if len(results) != 0 {
		t.Errorf("expected an empty results array for zero findings, got %d", len(results))
	}
}

func TestSARIFOnlyIncludesFailFindings(t *testing.T) {
	findings := []policy.Finding{
		{RuleID: "TA01", Status: policy.StatusPass, Location: collector.Location{File: "a.yaml", Line: 1}},
		{RuleID: "TA02", Status: policy.StatusFail, Location: collector.Location{File: "b.yaml", Line: 2}, Description: "bad", MapsToIssue: "goclaw#1070", HIPAACitation: "HIPAA Sec164.312(e)(1)"},
	}
	var buf bytes.Buffer
	if err := report.WriteSARIF(&buf, findings); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	run := doc["runs"].([]interface{})[0].(map[string]interface{})
	results := run["results"].([]interface{})
	if len(results) != 1 {
		t.Fatalf("expected exactly 1 SARIF result (only the FAIL, not the PASS), got %d", len(results))
	}
}
