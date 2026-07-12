package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestEndToEndBinary builds the real tenantguard binary and runs it via
// exec.Command against the bundled --demo deployment (all TA0N violations),
// asserting both terminal and SARIF output — not just calling run() in
// process, per the eng-review test plan's integration-test requirement.
func TestEndToEndBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary build in -short mode")
	}

	dir := t.TempDir()
	binPath := filepath.Join(dir, "tenantguard")

	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	// Terminal output: all 6 rules should FAIL against the bundled demo.
	termOut, err := exec.Command(binPath, "scan", "--demo").CombinedOutput()
	if err == nil {
		t.Fatalf("expected the demo scan to exit non-zero (findings present), got success. Output:\n%s", termOut)
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() != exitFindings {
		t.Errorf("exit code = %d, want %d (exitFindings)", exitErr.ExitCode(), exitFindings)
	}
	for _, rule := range []string{"TA01", "TA02", "TA03", "TA04", "TA05", "TA09", "TA10", "TA06"} {
		if !strings.Contains(string(termOut), rule) {
			t.Errorf("expected %s to appear in terminal output, got:\n%s", rule, termOut)
		}
	}

	// SARIF output: same scan, valid SARIF with 6 results.
	sarifPath := filepath.Join(dir, "report.sarif")
	sarifCmd := exec.Command(binPath, "scan", "--demo", "--format", "sarif", "--sarif-out", sarifPath)
	if out, err := sarifCmd.CombinedOutput(); err == nil {
		t.Fatalf("expected non-zero exit for the SARIF-format demo scan too, got success:\n%s", out)
	} else if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() != exitFindings {
		t.Errorf("SARIF-mode exit code = %d, want %d", exitErr.ExitCode(), exitFindings)
	}

	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("reading SARIF output: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}
	runs, _ := doc["runs"].([]interface{})
	if len(runs) != 1 {
		t.Fatalf("expected 1 SARIF run, got %d", len(runs))
	}
	results, _ := runs[0].(map[string]interface{})["results"].([]interface{})
	if len(results) != 9 {
		t.Errorf("expected 9 SARIF results (one per violated rule: TA01-06, TA09, TA10, TA13 -- TA08/TA12/TA14 declare no providers/resource-profiles or PASS cleanly so contribute none), got %d", len(results))
	}
}
