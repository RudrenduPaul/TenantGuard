package demo_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/RudrenduPaul/TenantGuard/internal/collector"
	"github.com/RudrenduPaul/TenantGuard/internal/demo"
)

func TestMaterializeWritesAScannableDeployment(t *testing.T) {
	dir, err := demo.Materialize()
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	if _, err := os.Stat(filepath.Join(dir, "deployment.yaml")); err != nil {
		t.Fatalf("expected deployment.yaml to exist in the materialized dir: %v", err)
	}

	cfg, err := collector.Collect(dir)
	if err != nil {
		t.Fatalf("the materialized demo deployment should be scannable: %v", err)
	}
	if len(cfg.Sandboxes) == 0 {
		t.Error("expected the demo deployment to contain at least one sandbox mount")
	}
}

func TestMaterializeIsIsolatedPerCall(t *testing.T) {
	dir1, err := demo.Materialize()
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir1) })
	dir2, err := demo.Materialize()
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir2) })

	if dir1 == dir2 {
		t.Error("each Materialize call should get its own temp directory, not share one")
	}
}
