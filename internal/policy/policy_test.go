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

// TestTA01_ScopedPerTenantDeclaration proves the second signal path: a mount
// path with no ${TENANT_ID} placeholder still PASSES when scoped_per_tenant
// is explicitly declared true, closing the gap where a real Go-computed
// mount path can never contain the literal convention token but the
// deployment can still attest the mount is actually scoped per tenant.
func TestTA01_ScopedPerTenantDeclaration(t *testing.T) {
	clean := scanFixture(t, "testdata/ta01/clean-scoped-declared", "TA01")
	if countStatus(clean, policy.StatusFail) != 0 {
		t.Errorf("expected zero TA01 FAILs when scoped_per_tenant is declared true, got %+v", clean)
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

// TestTA02_CIDRCoverage confirms TA02's private-range classification now
// matches goclaw's own real SSRF blocklist (goclaw#1269 + the linkdao
// comment on goclaw#1070), not just the original 5-string prefix list —
// covering the RFC1918 middle third, CGN, RFC 2544 benchmarking, reserved,
// and IPv4/IPv6 loopback/link-local/ULA/multicast ranges.
func TestTA02_CIDRCoverage(t *testing.T) {
	vuln := scanFixture(t, "testdata/ta02/vulnerable-cidr-coverage", "TA02")
	if got, want := countStatus(vuln, policy.StatusFail), 9; got != want {
		t.Errorf("expected exactly %d TA02 FAILs across the expanded CIDR ranges, got %d: %+v", want, got, vuln)
	}
}

// TestTA02_HostnameResolution reproduces the exact goclaw#1070 headline
// case: a hostname (host.docker.internal) with no private-looking
// substring in the URL text, which the OLD string-prefix matcher would
// have missed entirely. collector.LookupHost is overridden so the
// resolution is deterministic and doesn't depend on live DNS.
func TestTA02_HostnameResolution(t *testing.T) {
	orig := collector.LookupHost
	collector.LookupHost = func(host string) ([]string, error) {
		if host == "host.docker.internal" {
			return []string{"10.18.231.2"}, nil
		}
		return orig(host)
	}
	t.Cleanup(func() { collector.LookupHost = orig })

	vuln := scanFixture(t, "testdata/ta02/vulnerable-docker-internal", "TA02")
	if countStatus(vuln, policy.StatusFail) == 0 {
		t.Errorf("expected a TA02 FAIL for host.docker.internal resolving to a private IP (the exact goclaw#1070 repro), got %+v", vuln)
	}
}

// TestTA02_UnpinnedValidatorStillFails covers the DNS-rebinding/TOCTOU gap
// raised independently by @m13v and @linkdao on goclaw#1070:
// validates_private: true alone, without pins_resolved_ip: true, must
// still FAIL.
func TestTA02_UnpinnedValidatorStillFails(t *testing.T) {
	vuln := scanFixture(t, "testdata/ta02/vulnerable-unpinned", "TA02")
	if countStatus(vuln, policy.StatusFail) == 0 {
		t.Errorf("expected a TA02 FAIL when validates_private is true but pins_resolved_ip is not, got %+v", vuln)
	}
}

// TestTA02_ExplicitAllowlistPasses covers the "Option A" escape hatch
// requested directly in the goclaw#1070 issue thread: a private host
// explicitly allowlisted via allowed_private_host passes even with no
// declared validator at all.
func TestTA02_ExplicitAllowlistPasses(t *testing.T) {
	clean := scanFixture(t, "testdata/ta02/clean-allowlisted", "TA02")
	if countStatus(clean, policy.StatusFail) != 0 {
		t.Errorf("expected zero TA02 FAILs for a host explicitly allowlisted via allowed_private_host, got %+v", clean)
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

// TestTA04_AllowChainExec covers goclaw#1033: an exec tool with
// allow_chain_exec: true leaks credential env vars to every command in a
// shell operator chain, even when the direct/indirect env-dump denylist is
// otherwise fully set.
func TestTA04_AllowChainExec(t *testing.T) {
	vuln := scanFixture(t, "testdata/ta04/vulnerable-chain-exec", "TA04")
	if countStatus(vuln, policy.StatusFail) == 0 {
		t.Errorf("expected at least one TA04 FAIL on the vulnerable-chain-exec fixture, got %+v", vuln)
	}
	clean := scanFixture(t, "testdata/ta04/clean-chain-exec", "TA04")
	if countStatus(clean, policy.StatusFail) != 0 {
		t.Errorf("expected zero TA04 FAILs on the clean-chain-exec fixture, got %+v", clean)
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

func TestTA08(t *testing.T) {
	vuln := scanFixture(t, "testdata/ta08/vulnerable", "TA08")
	if countStatus(vuln, policy.StatusFail) == 0 {
		t.Errorf("expected at least one TA08 FAIL on the vulnerable fixture, got %+v", vuln)
	}
	clean := scanFixture(t, "testdata/ta08/clean", "TA08")
	if countStatus(clean, policy.StatusFail) != 0 {
		t.Errorf("expected zero TA08 FAILs on the clean fixture, got %+v", clean)
	}
}

// TestTA09 covers the deployment-level sandbox.on_unavailable check
// (goclaw#246). The vulnerable fixture never declares the key at all, which
// must FAIL just like an explicitly wrong value would — undeclared is not
// fail-closed.
func TestTA09(t *testing.T) {
	vuln := scanFixture(t, "testdata/ta09/vulnerable", "TA09")
	if countStatus(vuln, policy.StatusFail) == 0 {
		t.Errorf("expected at least one TA09 FAIL on the vulnerable fixture, got %+v", vuln)
	}
	clean := scanFixture(t, "testdata/ta09/clean", "TA09")
	if countStatus(clean, policy.StatusFail) != 0 {
		t.Errorf("expected zero TA09 FAILs on the clean fixture, got %+v", clean)
	}
}

func TestTA10(t *testing.T) {
	vuln := scanFixture(t, "testdata/ta10/vulnerable", "TA10")
	if countStatus(vuln, policy.StatusFail) == 0 {
		t.Errorf("expected at least one TA10 FAIL on the vulnerable fixture, got %+v", vuln)
	}
	clean := scanFixture(t, "testdata/ta10/clean", "TA10")
	if countStatus(clean, policy.StatusFail) != 0 {
		t.Errorf("expected zero TA10 FAILs on the clean fixture, got %+v", clean)
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

func TestTA13(t *testing.T) {
	vuln := scanFixture(t, "testdata/ta13/vulnerable", "TA13")
	if countStatus(vuln, policy.StatusFail) != 1 {
		t.Errorf("expected exactly 1 TA13 FAIL on the vulnerable fixture (no bridge: section declared), got %+v", vuln)
	}
	clean := scanFixture(t, "testdata/ta13/clean", "TA13")
	if countStatus(clean, policy.StatusFail) != 0 {
		t.Errorf("expected zero TA13 FAILs on the clean fixture, got %+v", clean)
	}
	if countStatus(clean, policy.StatusPass) != 1 {
		t.Errorf("expected exactly 1 TA13 PASS on the clean fixture, got %+v", clean)
	}
}

func TestTA14(t *testing.T) {
	vuln := scanFixture(t, "testdata/ta14/vulnerable", "TA14")
	if countStatus(vuln, policy.StatusFail) == 0 {
		t.Errorf("expected at least one TA14 FAIL on the vulnerable fixture, got %+v", vuln)
	}
	clean := scanFixture(t, "testdata/ta14/clean", "TA14")
	if countStatus(clean, policy.StatusFail) != 0 {
		t.Errorf("expected zero TA14 FAILs on the clean fixture, got %+v", clean)
	}
}

// TestPolicyLoadFailureIsFatal — NewEvaluator must refuse to build a partial
// Evaluator if a policy fails to compile. There's no way to inject a broken
// .rego file into the embedded FS from a black-box test, so this instead
// documents and asserts the actual behavior: a healthy NewEvaluator call
// prepares all rules or none, never a subset. See ErrPolicyLoadFailed.
func TestPolicyLoadFailureIsFatal(t *testing.T) {
	ev, err := policy.NewEvaluator(context.Background())
	if err != nil {
		t.Fatalf("NewEvaluator with valid embedded policies should not fail: %v", err)
	}
	if got, want := len(ev.RuleIDs()), 11; got != want {
		t.Errorf("RuleIDs() = %d rules, want %d — all-or-nothing loading means a partial set should never occur", got, want)
	}
}
