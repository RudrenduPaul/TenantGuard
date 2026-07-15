package report

import (
	"encoding/json"
	"io"

	"github.com/RudrenduPaul/TenantGuard/internal/policy"
)

// jsonFinding is the wire shape of one finding in --format json output. It
// flattens collector.Location into file/line and always includes both PASS
// and FAIL findings (unlike SARIF, which only emits FAIL as a "result") so an
// agent parsing this mode gets the same "checked vs. failed" picture the
// terminal report gives a human, without needing to also compute a diff
// against RuleIDs() to find what passed.
type jsonFinding struct {
	RuleID        string `json:"rule_id"`
	Status        string `json:"status"`
	File          string `json:"file"`
	Line          int    `json:"line"`
	Description   string `json:"description,omitempty"`
	MapsToIssue   string `json:"maps_to_issue,omitempty"`
	HIPAACitation string `json:"hipaa_citation,omitempty"`
	Provisional   bool   `json:"provisional"`
}

// jsonReport is the top-level --format json document: a target, a
// fail/pass summary (so an agent doesn't have to recount the findings array
// to answer "did this scan pass"), and the flat findings list itself.
type jsonReport struct {
	Target   string        `json:"target"`
	Summary  jsonSummary   `json:"summary"`
	Findings []jsonFinding `json:"findings"`
}

type jsonSummary struct {
	Fail int `json:"fail"`
	Pass int `json:"pass"`
}

// WriteJSON renders findings as a single structured JSON document to w — a
// plain, schema-light alternative to --format sarif for callers (agents,
// scripts) that just want raw pass/fail results without SARIF's
// tool/run/rule/taxonomy object model. Both PASS and FAIL findings are
// included, matching WriteTerminal's behavior, not just failures like
// WriteSARIF.
func WriteJSON(w io.Writer, target string, findings []policy.Finding) error {
	out := jsonReport{
		Target:   target,
		Findings: []jsonFinding{},
	}

	for _, f := range findings {
		if f.Status == policy.StatusFail {
			out.Summary.Fail++
		} else {
			out.Summary.Pass++
		}
		out.Findings = append(out.Findings, jsonFinding{
			RuleID:        f.RuleID,
			Status:        f.Status,
			File:          f.Location.File,
			Line:          f.Location.Line,
			Description:   f.Description,
			MapsToIssue:   f.MapsToIssue,
			HIPAACitation: f.HIPAACitation,
			Provisional:   f.Provisional,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
