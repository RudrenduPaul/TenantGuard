package collector_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/RudrenduPaul/TenantGuard/internal/collector"
)

func TestMalformedConfigFailsLoudly(t *testing.T) {
	_, err := collector.Collect("testdata/malformed")
	if err == nil {
		t.Fatal("expected an error for malformed YAML, got nil")
	}
	var malformed *collector.ErrMalformedConfig
	if !errors.As(err, &malformed) {
		t.Fatalf("expected *ErrMalformedConfig, got %T: %v", err, err)
	}
	if !filepath.IsAbs(malformed.File) && malformed.File == "" {
		t.Error("ErrMalformedConfig.File should name the offending file")
	}
}

func TestEmptyTargetErrors(t *testing.T) {
	_, err := collector.Collect("testdata/empty")
	if err == nil {
		t.Fatal("expected an error for a target with no config files, got nil (a 0-finding PASS must never mean 'nothing was scanned')")
	}
	var noConfig *collector.ErrNoConfigFound
	if !errors.As(err, &noConfig) {
		t.Fatalf("expected *ErrNoConfigFound, got %T: %v", err, err)
	}
}

func TestTargetMustBeDirectory(t *testing.T) {
	_, err := collector.Collect("testdata/malformed/deployment.yaml")
	if err == nil {
		t.Fatal("expected an error when target is a file, not a directory")
	}
}

func TestUnknownFieldsWarnNotFail(t *testing.T) {
	cfg, err := collector.Collect("testdata/unknownfields")
	if err != nil {
		t.Fatalf("unrecognized fields should warn, not fail the scan: %v", err)
	}
	if len(cfg.Warnings) == 0 {
		t.Error("expected at least one warning about an unrecognized field")
	}
	if len(cfg.Sandboxes) != 1 || cfg.Sandboxes[0].Path != "/shared/${TENANT_ID}/workspace" {
		t.Errorf("recognized fields should still be collected despite the unknown ones present: %+v", cfg.Sandboxes)
	}
}

func TestCrossFileCorrelation(t *testing.T) {
	// TA03 needs CronSchedules and Agents to be visible in the SAME merged
	// document even when a real deployment splits them across separate
	// files — this is the entire reason collection happens once, upfront.
	cfg, err := collector.Collect("testdata/multifile")
	if err != nil {
		t.Fatalf("collector.Collect: %v", err)
	}
	if len(cfg.CronSchedules) != 1 {
		t.Fatalf("expected 1 cron schedule collected across files, got %d", len(cfg.CronSchedules))
	}
	if len(cfg.Agents) != 1 {
		t.Fatalf("expected 1 agent collected across files, got %d", len(cfg.Agents))
	}
	if cfg.CronSchedules[0].TargetAgent != cfg.Agents[0].Name {
		t.Errorf("cron target_agent %q should match the agent declared in a different file %q",
			cfg.CronSchedules[0].TargetAgent, cfg.Agents[0].Name)
	}
}

func TestLocationTracksRealLine(t *testing.T) {
	cfg, err := collector.Collect("testdata/unknownfields")
	if err != nil {
		t.Fatalf("collector.Collect: %v", err)
	}
	if len(cfg.Sandboxes) != 1 {
		t.Fatalf("expected 1 sandbox mount, got %d", len(cfg.Sandboxes))
	}
	// The mount entry is on line 3 of testdata/unknownfields/deployment.yaml —
	// a Finding must be able to cite this exact line, not just the file.
	if got := cfg.Sandboxes[0].Location.Line; got != 3 {
		t.Errorf("Location.Line = %d, want 3 (the actual line of the mount entry in the fixture)", got)
	}
}

// TestMCPToolResolvesLiteralIP confirms that an MCP tool URL with a literal
// IP host is captured in ResolvedIPs at collection time (Go's resolver
// short-circuits literal IPs with no network call, so this is fast and
// deterministic without any LookupHost override).
func TestMCPToolResolvesLiteralIP(t *testing.T) {
	cfg, err := collector.Collect("../policy/testdata/ta02/clean")
	if err != nil {
		t.Fatalf("collector.Collect: %v", err)
	}
	var found bool
	for _, m := range cfg.MCPTools {
		if m.URL == "http://127.0.0.1:9000/tools" {
			found = true
			if len(m.ResolvedIPs) != 1 || m.ResolvedIPs[0] != "127.0.0.1" {
				t.Errorf("expected ResolvedIPs = [127.0.0.1] for a literal-IP URL, got %v", m.ResolvedIPs)
			}
			if !m.ValidatesPrivate || !m.PinsResolvedIP {
				t.Errorf("expected ValidatesPrivate and PinsResolvedIP both true from the fixture YAML, got validates_private=%v pins_resolved_ip=%v", m.ValidatesPrivate, m.PinsResolvedIP)
			}
		}
	}
	if !found {
		t.Fatal("expected to find the 127.0.0.1 MCP tool entry from testdata/ta02/clean")
	}
}

// TestAllowedPrivateHostFieldParses confirms tools.mcp[].allowed_private_host
// in YAML flows through to MCPToolEntry.ExplicitlyAllowedHost.
func TestAllowedPrivateHostFieldParses(t *testing.T) {
	cfg, err := collector.Collect("../policy/testdata/ta02/clean-allowlisted")
	if err != nil {
		t.Fatalf("collector.Collect: %v", err)
	}
	if len(cfg.MCPTools) != 1 {
		t.Fatalf("expected 1 MCP tool, got %d", len(cfg.MCPTools))
	}
	if !cfg.MCPTools[0].ExplicitlyAllowedHost {
		t.Error("expected allowed_private_host: true in YAML to set ExplicitlyAllowedHost")
	}
}

// TestCollectFromGoclawEnv is a best-effort, additive enrichment step (goclaw
// PR #1248): it must flip ExplicitlyAllowedHost on any MCP tool whose
// hostname matches (case-insensitively) an entry in the real
// GOCLAW_MCP_ALLOWED_HOSTS env var, and must leave Collect()'s own YAML-only
// behavior completely unaffected when the env var is unset.
func TestCollectFromGoclawEnv(t *testing.T) {
	orig := collector.LookupHost
	collector.LookupHost = func(host string) ([]string, error) {
		return nil, fmt.Errorf("dns disabled in test")
	}
	t.Cleanup(func() { collector.LookupHost = orig })

	cfg, err := collector.Collect("testdata/mcpenv")
	if err != nil {
		t.Fatalf("collector.Collect: %v", err)
	}
	if len(cfg.MCPTools) != 2 {
		t.Fatalf("expected 2 MCP tools collected, got %d", len(cfg.MCPTools))
	}
	for _, m := range cfg.MCPTools {
		if m.ExplicitlyAllowedHost {
			t.Fatalf("ExplicitlyAllowedHost should be false before CollectFromGoclawEnv runs, got true for %s", m.URL)
		}
	}

	t.Setenv("GOCLAW_MCP_ALLOWED_HOSTS", "Mcp.Internal.Example.Com, other.example.com")
	if err := collector.CollectFromGoclawEnv(cfg); err != nil {
		t.Fatalf("CollectFromGoclawEnv: %v", err)
	}

	var matched, unmatched bool
	for _, m := range cfg.MCPTools {
		switch m.URL {
		case "https://mcp.internal.example.com/tools":
			matched = m.ExplicitlyAllowedHost
		case "https://unrelated.example.com/tools":
			unmatched = m.ExplicitlyAllowedHost
		}
	}
	if !matched {
		t.Error("expected the tool whose hostname appears (case-insensitively) in GOCLAW_MCP_ALLOWED_HOSTS to have ExplicitlyAllowedHost = true")
	}
	if unmatched {
		t.Error("expected the tool whose hostname does NOT appear in GOCLAW_MCP_ALLOWED_HOSTS to stay ExplicitlyAllowedHost = false")
	}
}
