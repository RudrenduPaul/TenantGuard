package report_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/RudrenduPaul/TenantGuard/internal/collector"
	"github.com/RudrenduPaul/TenantGuard/internal/policy"
	"github.com/RudrenduPaul/TenantGuard/internal/report"
)

func TestWriteJSONIncludesBothPassAndFail(t *testing.T) {
	findings := []policy.Finding{
		{RuleID: "TA01", Status: policy.StatusFail, Location: collector.Location{File: "a.yaml", Line: 3}, Description: "no tenant scoping", MapsToIssue: "goclaw#1163", HIPAACitation: "HIPAA Sec164.312(a)(1)", Provisional: true},
		{RuleID: "TA02", Status: policy.StatusPass, Location: collector.Location{File: "b.yaml", Line: 5}},
	}
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, "/some/target", findings); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var doc struct {
		Target  string `json:"target"`
		Summary struct {
			Fail int `json:"fail"`
			Pass int `json:"pass"`
		} `json:"summary"`
		Findings []struct {
			RuleID        string `json:"rule_id"`
			Status        string `json:"status"`
			File          string `json:"file"`
			Line          int    `json:"line"`
			Description   string `json:"description"`
			MapsToIssue   string `json:"maps_to_issue"`
			HIPAACitation string `json:"hipaa_citation"`
			Provisional   bool   `json:"provisional"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}

	if doc.Target != "/some/target" {
		t.Errorf("expected target /some/target, got %q", doc.Target)
	}
	if doc.Summary.Fail != 1 || doc.Summary.Pass != 1 {
		t.Errorf("expected summary {fail:1 pass:1}, got %+v", doc.Summary)
	}
	if len(doc.Findings) != 2 {
		t.Fatalf("expected 2 findings (both PASS and FAIL, unlike SARIF), got %d", len(doc.Findings))
	}
	if doc.Findings[0].RuleID != "TA01" || doc.Findings[0].Status != "FAIL" || doc.Findings[0].File != "a.yaml" || doc.Findings[0].Line != 3 {
		t.Errorf("unexpected first finding: %+v", doc.Findings[0])
	}
	if doc.Findings[1].RuleID != "TA02" || doc.Findings[1].Status != "PASS" {
		t.Errorf("unexpected second finding: %+v", doc.Findings[1])
	}
}

func TestWriteJSONEmptyFindingsProducesEmptyArrayNotNull(t *testing.T) {
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, "/some/target", nil); err != nil {
		t.Fatalf("WriteJSON with no findings should not error: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	findings, ok := doc["findings"].([]interface{})
	if !ok {
		t.Fatalf("expected findings to be a JSON array (not null), got %v", doc["findings"])
	}
	if len(findings) != 0 {
		t.Errorf("expected empty findings array, got %d entries", len(findings))
	}
}
