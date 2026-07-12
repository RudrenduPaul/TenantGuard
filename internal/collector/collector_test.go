package collector_test

import (
	"errors"
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
