package policy

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/RudrenduPaul/TenantGuard/internal/collector"
)

//go:embed rego/*.rego
var regoFS embed.FS

// ruleOrder is fixed so terminal/SARIF output is always in the same order,
// and so a policy load failure can name exactly which rule failed to prepare.
var ruleOrder = []string{"TA01", "TA02", "TA03", "TA04", "TA05", "TA14"}

// preparedRule pairs a rule ID with its compiled query, built once at
// Evaluator construction via PrepareForEval — per OPA's own documented
// pattern, this avoids re-parsing and re-compiling the policy on every scan.
type preparedRule struct {
	id    string
	query rego.PreparedEvalQuery
}

// Evaluator holds one prepared query per TA0N rule. Safe to reuse across
// scans and across goroutines (prepared queries are documented as
// goroutine-safe by OPA).
type Evaluator struct {
	rules []preparedRule
}

// ErrPolicyLoadFailed means a rule's Rego source failed to parse or compile.
// The scanner must refuse to run ANY rule when this happens — a scanner that
// silently drops one broken rule while running the other four is worse than
// one that fails all five loudly.
type ErrPolicyLoadFailed struct {
	RuleID string
	Err    error
}

func (e *ErrPolicyLoadFailed) Error() string {
	return fmt.Sprintf("policy %s failed to load: %v", e.RuleID, e.Err)
}

func (e *ErrPolicyLoadFailed) Unwrap() error { return e.Err }

// NewEvaluator compiles all five TA0N policies. If any one fails to compile,
// it returns an error and no partially-usable Evaluator — see
// ErrPolicyLoadFailed.
func NewEvaluator(ctx context.Context) (*Evaluator, error) {
	ev := &Evaluator{}
	for _, id := range ruleOrder {
		src, err := regoFS.ReadFile(fmt.Sprintf("rego/%s.rego", lower(id)))
		if err != nil {
			return nil, &ErrPolicyLoadFailed{RuleID: id, Err: err}
		}
		query, err := rego.New(
			rego.Query(fmt.Sprintf("data.tenantguard.%s.violations", lower(id))),
			rego.Module(fmt.Sprintf("%s.rego", lower(id)), string(src)),
		).PrepareForEval(ctx)
		if err != nil {
			return nil, &ErrPolicyLoadFailed{RuleID: id, Err: err}
		}
		ev.rules = append(ev.rules, preparedRule{id: id, query: query})
	}
	return ev, nil
}

// RuleIDs returns the fixed rule order — used to report which rules actually
// ran vs. didn't on a partial-failure scan.
func (e *Evaluator) RuleIDs() []string {
	return ruleOrder
}

// Evaluate runs every prepared rule against cfg and returns one Finding per
// evaluated array entry (both PASS and FAIL), so the caller always knows
// which entries were checked, not just which ones failed.
func (e *Evaluator) Evaluate(ctx context.Context, cfg *collector.CollectedConfig) ([]Finding, error) {
	input := toRegoInput(cfg)
	var findings []Finding

	for _, r := range e.rules {
		results, err := r.query.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			return nil, fmt.Errorf("evaluating %s: %w", r.id, err)
		}

		violationSet := extractViolations(results)

		switch r.id {
		case "TA01":
			findings = append(findings, buildFindings(r.id, len(cfg.Sandboxes), violationSet, func(i int) collector.Location {
				return cfg.Sandboxes[i].Location
			})...)
		case "TA02":
			findings = append(findings, buildFindings(r.id, len(cfg.MCPTools), violationSet, func(i int) collector.Location {
				return cfg.MCPTools[i].Location
			})...)
		case "TA03":
			findings = append(findings, buildFindings(r.id, len(cfg.CronSchedules), violationSet, func(i int) collector.Location {
				return cfg.CronSchedules[i].Location
			})...)
		case "TA04":
			findings = append(findings, buildFindings(r.id, len(cfg.ExecTools), violationSet, func(i int) collector.Location {
				return cfg.ExecTools[i].Location
			})...)
		case "TA05":
			findings = append(findings, buildTA05Findings(cfg, results)...)
		case "TA14":
			findings = append(findings, buildFindings(r.id, len(cfg.ResourceProfiles), violationSet, func(i int) collector.Location {
				return cfg.ResourceProfiles[i].Location
			})...)
		}
	}
	return findings, nil
}

// extractViolations reads a simple `violations contains <int>` result set
// (used by TA01-TA04) into a Go set of indices.
func extractViolations(results rego.ResultSet) map[int]bool {
	set := map[int]bool{}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return set
	}
	raw, ok := results[0].Expressions[0].Value.([]interface{})
	if !ok {
		return set
	}
	for _, v := range raw {
		if i, ok := toInt(v); ok {
			set[i] = true
		}
	}
	return set
}

// toInt converts a decoded Rego number to a Go int. OPA's rego.ResultSet
// represents Rego integers as json.Number (a string-based type, to preserve
// arbitrary precision) in most configurations, not float64 — handle both so
// this doesn't silently break if that representation ever changes.
func toInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	case float64:
		return int(n), true
	case int:
		return n, true
	default:
		return 0, false
	}
}

// buildFindings produces one Finding per index 0..total-1: FAIL if present in
// violations, PASS otherwise. This is what lets --format terminal show "3
// PASS, 2 FAIL" instead of only ever showing failures.
func buildFindings(ruleID string, total int, violations map[int]bool, locate func(int) collector.Location) []Finding {
	meta := ruleMetadata[ruleID]
	var out []Finding
	for i := 0; i < total; i++ {
		status := StatusPass
		if violations[i] {
			status = StatusFail
		}
		out = append(out, Finding{
			RuleID:      ruleID,
			Status:      status,
			Location:    locate(i),
			Description: meta.description,
			MapsToIssue: meta.mapsToIssue,
			Provisional: true,
		})
	}
	return out
}

// buildTA05Findings handles TA05's nested {exec_index, approval_index} result
// shape, which extractViolations' flat-index model doesn't cover.
func buildTA05Findings(cfg *collector.CollectedConfig, results rego.ResultSet) []Finding {
	meta := ruleMetadata["TA05"]
	violations := map[[2]int]bool{}
	if len(results) > 0 && len(results[0].Expressions) > 0 {
		if raw, ok := results[0].Expressions[0].Value.([]interface{}); ok {
			for _, v := range raw {
				obj, ok := v.(map[string]interface{})
				if !ok {
					continue
				}
				ei, eiOK := toInt(obj["exec_index"])
				ai, aiOK := toInt(obj["approval_index"])
				if !eiOK || !aiOK {
					continue
				}
				violations[[2]int{ei, ai}] = true
			}
		}
	}

	var out []Finding
	for ei, tool := range cfg.ExecTools {
		for ai, appr := range tool.Approvals {
			status := StatusPass
			if violations[[2]int{ei, ai}] {
				status = StatusFail
			}
			out = append(out, Finding{
				RuleID:      "TA05",
				Status:      status,
				Location:    appr.Location,
				Description: meta.description,
				MapsToIssue: meta.mapsToIssue,
				Provisional: true,
			})
		}
	}
	return out
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
