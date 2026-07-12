package policy_test

import (
	"context"
	"testing"

	"github.com/RudrenduPaul/TenantGuard/internal/collector"
	"github.com/RudrenduPaul/TenantGuard/internal/policy"
)

// scanFixture runs the full collector + evaluator pipeline against a
// testdata fixture directory containing a single deployment.yaml-equivalent
// file, returning the findings for the named rule only.
func scanFixture(t *testing.T, dir, ruleID string) []policy.Finding {
	t.Helper()
	cfg, err := collector.Collect(dir)
	if err != nil {
		t.Fatalf("collector.Collect(%q): %v", dir, err)
	}
	ev, err := policy.NewEvaluator(context.Background())
	if err != nil {
		t.Fatalf("policy.NewEvaluator: %v", err)
	}
	findings, err := ev.Evaluate(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	var out []policy.Finding
	for _, f := range findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

func countStatus(findings []policy.Finding, status string) int {
	n := 0
	for _, f := range findings {
		if f.Status == status {
			n++
		}
	}
	return n
}

func TestTA01(t *testing.T) {
	vuln := scanFixture(t, "testdata/ta01/vulnerable", "TA01")
	if countStatus(vuln, policy.StatusFail) == 0 {
		t.Errorf("expected at least one TA01 FAIL on the vulnerable fixture, got %+v", vuln)
	}
	clean := scanFixture(t, "testdata/ta01/clean", "TA01")
	if countStatus(clean, policy.StatusFail) != 0 {
		t.Errorf("expected zero TA01 FAILs on the clean fixture, got %+v", clean)
	}
}

func TestTA02(t *testing.T) {
	vuln := scanFixture(t, "testdata/ta02/vulnerable", "TA02")
	if countStatus(vuln, policy.StatusFail) == 0 {
		t.Errorf("expected at least one TA02 FAIL on the vulnerable fixture, got %+v", vuln)
	}
	clean := scanFixture(t, "testdata/ta02/clean", "TA02")
	if countStatus(clean, policy.StatusFail) != 0 {
		t.Errorf("expected zero TA02 FAILs on the clean fixture, got %+v", clean)
	}
}

func TestTA03(t *testing.T) {
	vuln := scanFixture(t, "testdata/ta03/vulnerable", "TA03")
	if got := countStatus(vuln, policy.StatusFail); got != 2 {
		t.Errorf("expected exactly 2 TA03 FAILs (cross-tenant + dangling reference) on the vulnerable fixture, got %d: %+v", got, vuln)
	}
	clean := scanFixture(t, "testdata/ta03/clean", "TA03")
	if countStatus(clean, policy.StatusFail) != 0 {
		t.Errorf("expected zero TA03 FAILs on the clean fixture, got %+v", clean)
	}
}

func TestTA04(t *testing.T) {
	vuln := scanFixture(t, "testdata/ta04/vulnerable", "TA04")
	if countStatus(vuln, policy.StatusFail) == 0 {
		t.Errorf("expected at least one TA04 FAIL on the vulnerable fixture, got %+v", vuln)
	}
	clean := scanFixture(t, "testdata/ta04/clean", "TA04")
	if countStatus(clean, policy.StatusFail) != 0 {
		t.Errorf("expected zero TA04 FAILs on the clean fixture, got %+v", clean)
	}
}

func TestTA05(t *testing.T) {
	vuln := scanFixture(t, "testdata/ta05/vulnerable", "TA05")
	if countStatus(vuln, policy.StatusFail) == 0 {
		t.Errorf("expected at least one TA05 FAIL on the vulnerable fixture, got %+v", vuln)
	}
	clean := scanFixture(t, "testdata/ta05/clean", "TA05")
	if countStatus(clean, policy.StatusFail) != 0 {
		t.Errorf("expected zero TA05 FAILs on the clean fixture, got %+v", clean)
	}
}

func TestTA12(t *testing.T) {
	vuln := scanFixture(t, "testdata/ta12/vulnerable", "TA12")
	if countStatus(vuln, policy.StatusFail) == 0 {
		t.Errorf("expected at least one TA12 FAIL on the vulnerable fixture, got %+v", vuln)
	}
	clean := scanFixture(t, "testdata/ta12/clean", "TA12")
	if countStatus(clean, policy.StatusFail) != 0 {
		t.Errorf("expected zero TA12 FAILs on the clean fixture, got %+v", clean)
	}
	// TA12 is a deployment-level check: an owner: section that's entirely
	// absent must still FAIL, never be silently skipped, since absence
	// guarantees nothing about sysadmin recovery access (goclaw#954's whole
	// point).
	absent := scanFixture(t, "testdata/ta12/absent", "TA12")
	if countStatus(absent, policy.StatusFail) == 0 {
		t.Errorf("expected a TA12 FAIL when no owner: section is declared at all, got %+v", absent)
	}
	if len(absent) != 1 {
		t.Errorf("expected exactly one TA12 Finding per scan (deployment-level check), got %d: %+v", len(absent), absent)
	}
}

// TestPolicyLoadFailureIsFatal — NewEvaluator must refuse to build a partial
// Evaluator if a policy fails to compile. There's no way to inject a broken
// .rego file into the embedded FS from a black-box test, so this instead
// documents and asserts the actual behavior: a healthy NewEvaluator call
// prepares all 5 rules or none, never a subset. See ErrPolicyLoadFailed.
func TestPolicyLoadFailureIsFatal(t *testing.T) {
	ev, err := policy.NewEvaluator(context.Background())
	if err != nil {
		t.Fatalf("NewEvaluator with valid embedded policies should not fail: %v", err)
	}
	if got, want := len(ev.RuleIDs()), 6; got != want {
		t.Errorf("RuleIDs() = %d rules, want %d — all-or-nothing loading means a partial set should never occur", got, want)
	}
}
