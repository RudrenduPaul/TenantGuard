package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestUsageWithNoArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(nil, &out, &errOut)
	if code != exitScanError {
		t.Errorf("code = %d, want %d (exitScanError)", code, exitScanError)
	}
	if !strings.Contains(errOut.String(), "usage:") {
		t.Errorf("expected usage message, got %q", errOut.String())
	}
}

func TestTargetRequiredWithoutDemo(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"scan"}, &out, &errOut)
	if code != exitScanError {
		t.Errorf("code = %d, want %d", code, exitScanError)
	}
	if !strings.Contains(errOut.String(), "--target or --demo is required") {
		t.Errorf("expected a clear error about the missing --target/--demo, got %q", errOut.String())
	}
}

func TestTargetAndDemoMutuallyExclusive(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"scan", "--target", "testdata", "--demo"}, &out, &errOut)
	if code != exitScanError {
		t.Errorf("code = %d, want %d", code, exitScanError)
	}
	if !strings.Contains(errOut.String(), "mutually exclusive") {
		t.Errorf("expected a mutually-exclusive-flags error, got %q", errOut.String())
	}
}

func TestTargetMustBeDirectory(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"scan", "--target", "main_test.go"}, &out, &errOut)
	if code != exitScanError {
		t.Errorf("code = %d, want %d", code, exitScanError)
	}
	if !strings.Contains(errOut.String(), "must be a directory") {
		t.Errorf("expected a target-must-be-directory error, got %q", errOut.String())
	}
}

func TestDemoModeExitsWithFindings(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"scan", "--demo"}, &out, &errOut)
	if code != exitFindings {
		t.Errorf("code = %d, want %d (exitFindings) — the bundled demo deployment has 5 known violations, stderr=%q", code, exitFindings, errOut.String())
	}
	if !strings.Contains(out.String(), "FAIL") {
		t.Errorf("expected FAIL findings in terminal output, got %q", out.String())
	}
}

func TestCleanTargetExitsZero(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"scan", "--target", "testdata/clean"}, &out, &errOut)
	if code != exitClean {
		t.Errorf("code = %d, want %d (exitClean), stderr=%q", code, exitClean, errOut.String())
	}
	// Check for the per-finding "[FAIL]" marker, not the bare substring
	// "FAIL" — the summary line always reads "0 FAIL, N PASS" even on a
	// fully clean scan, which would false-positive a plain Contains(_, "FAIL").
	if strings.Contains(out.String(), "[FAIL]") {
		t.Errorf("expected no FAIL findings on a clean target, got %q", out.String())
	}
}
