// Package report renders scan findings as human-readable terminal output and
// as SARIF 2.1.0 (via github.com/owenrumney/go-sarif/v3), reusing a
// maintained library for the SARIF object model instead of hand-rolling the
// schema — see tenantguard-eng-review-2026-07-11.md, Search Before Building.
package report

import (
	"io"

	sarif "github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/RudrenduPaul/TenantGuard/internal/policy"
)

const toolName = "tenantguard"
const informationURI = "https://github.com/RudrenduPaul/TenantGuard"
const hipaaTaxonomyName = "hipaa-security-rule"
const hipaaTaxonomyFullName = "HIPAA Security Rule (provisional, TenantGuard's own interpretation)"

// WriteSARIF renders findings as a SARIF 2.1.0 log to w. Only FAIL findings
// become SARIF results — matching SARIF's own convention that results
// represent problems found, not a record of every check that passed.
func WriteSARIF(w io.Writer, findings []policy.Finding) error {
	run := sarif.NewRunWithInformationURI(toolName, informationURI)

	for _, id := range []string{"TA01", "TA02", "TA03", "TA04", "TA05", "TA08", "TA09", "TA10", "TA12", "TA13", "TA14", "TA06", "TA07"} {
		run.AddRule(id)
	}

	hipaaTaxonomy := sarif.NewToolComponent().WithName(hipaaTaxonomyName).WithFullName(hipaaTaxonomyFullName)
	citationSeen := map[string]bool{}
	for _, f := range findings {
		if f.Status != policy.StatusFail || f.HIPAACitation == "" || citationSeen[f.HIPAACitation] {
			continue
		}
		citationSeen[f.HIPAACitation] = true
		hipaaTaxonomy.AddTaxa(sarif.NewReportingDescriptor().WithID(f.HIPAACitation).WithName(f.HIPAACitation))
	}
	run.AddTaxonomie(hipaaTaxonomy)

	for _, f := range findings {
		if f.Status != policy.StatusFail {
			continue
		}
		// NewRuleResult (not CreateResultForRule) — the latter reuses/caches
		// a single Result per ruleID, which would silently merge multiple
		// distinct findings under the same rule into one SARIF result.
		result := sarif.NewRuleResult(f.RuleID).
			WithMessage(sarif.NewTextMessage(f.Description)).
			WithLevel("error")

		physical := sarif.NewPhysicalLocation()
		physical.ArtifactLocation = sarif.NewSimpleArtifactLocation(f.Location.File)
		if f.Location.Line > 0 {
			physical.Region = sarif.NewSimpleRegion(f.Location.Line, f.Location.Line)
		}
		result.AddLocation(sarif.NewLocationWithPhysicalLocation(physical))

		if f.HIPAACitation != "" {
			ref := sarif.NewReportingDescriptorReference().
				WithID(f.HIPAACitation).
				WithToolComponent(sarif.NewToolComponentReference().WithName(hipaaTaxonomyName))
			result.AddTaxa(ref)
		}

		result.WithProperties(&sarif.PropertyBag{
			Properties: sarif.Properties{
				"maps_to_issue": f.MapsToIssue,
				"provisional":   f.Provisional,
			},
		})

		run.AddResult(result)
	}

	rep := sarif.NewReport()
	rep.AddRun(run)
	return rep.Write(w)
}
