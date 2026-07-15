// Command tenantguard scans a self-hosted multi-tenant AI-agent deployment's
// configuration for confirmed tenant-isolation defects (16 rules, TA01-TA16),
// each mapped to a goclaw GitHub issue or pull request that reproduces the
// same failure mode, and reports findings with an optional (provisional,
// unverified) HIPAA Sec164.312 citation.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/RudrenduPaul/TenantGuard/internal/collector"
	"github.com/RudrenduPaul/TenantGuard/internal/compliance"
	"github.com/RudrenduPaul/TenantGuard/internal/demo"
	"github.com/RudrenduPaul/TenantGuard/internal/policy"
	"github.com/RudrenduPaul/TenantGuard/internal/report"
)

// Exit codes distinguish "found problems" from "couldn't scan at all" — a CI
// gate needs to tell these apart, not just see a non-zero code.
const (
	exitClean     = 0
	exitFindings  = 1
	exitScanError = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// errf writes a formatted message to w. Terminal write errors here are not
// actionable (nothing sensible to do if stderr itself fails), so the return
// value is deliberately discarded — this is the single place that happens,
// rather than scattering `_, _ =` across every call site.
func errf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "scan" {
		errf(stderr, "usage: tenantguard scan [--target DIR | --demo] [--format terminal|sarif|json] [--control hipaa]\n")
		return exitScanError
	}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	target := fs.String("target", "", "path to the deployment config directory to scan")
	demoMode := fs.Bool("demo", false, "scan a bundled synthetic deployment instead of --target (zero setup)")
	format := fs.String("format", "terminal", "output format: terminal, sarif, or json")
	control := fs.String("control", "", "compliance framework to cite (hipaa)")
	sarifOut := fs.String("sarif-out", "tenantguard-report.sarif", "file to write SARIF output to when --format=sarif")

	if err := fs.Parse(args[1:]); err != nil {
		return exitScanError
	}

	if !*demoMode && *target == "" {
		errf(stderr, "error: either --target or --demo is required\n")
		return exitScanError
	}
	if *demoMode && *target != "" {
		errf(stderr, "error: --target and --demo are mutually exclusive\n")
		return exitScanError
	}

	scanTarget := *target
	if *demoMode {
		dir, err := demo.Materialize()
		if err != nil {
			errf(stderr, "error: failed to materialize demo deployment: %v\n", err)
			return exitScanError
		}
		defer func() { _ = os.RemoveAll(dir) }()
		scanTarget = dir
	}

	info, err := os.Stat(scanTarget)
	if err != nil {
		errf(stderr, "error: %v\n", err)
		return exitScanError
	}
	if !info.IsDir() {
		errf(stderr, "error: target must be a directory\n")
		return exitScanError
	}

	ctx := context.Background()

	cfg, err := collector.Collect(scanTarget)
	if err != nil {
		errf(stderr, "error: %v\n", err)
		return exitScanError
	}
	for _, w := range cfg.Warnings {
		errf(stderr, "warning: %s\n", w)
	}

	evaluator, err := policy.NewEvaluator(ctx)
	if err != nil {
		errf(stderr, "error: %v\n", err)
		return exitScanError
	}

	findings, err := evaluator.Evaluate(ctx, cfg)
	if err != nil {
		errf(stderr, "error: %v\n", err)
		return exitScanError
	}

	if *control == "hipaa" || *control == "" {
		compliance.Annotate(findings)
	}

	switch *format {
	case "sarif":
		f, err := os.Create(*sarifOut)
		if err != nil {
			errf(stderr, "error: %v\n", err)
			return exitScanError
		}
		writeErr := report.WriteSARIF(f, findings)
		closeErr := f.Close()
		if writeErr != nil {
			errf(stderr, "error: %v\n", writeErr)
			return exitScanError
		}
		if closeErr != nil {
			errf(stderr, "error: failed to finalize %s: %v\n", *sarifOut, closeErr)
			return exitScanError
		}
		errf(stdout, "SARIF report written to %s\n", *sarifOut)
	case "json":
		if err := report.WriteJSON(stdout, scanTarget, findings); err != nil {
			errf(stderr, "error: %v\n", err)
			return exitScanError
		}
	default:
		report.WriteTerminal(stdout, scanTarget, findings)
	}

	for _, f := range findings {
		if f.Status == policy.StatusFail {
			return exitFindings
		}
	}
	return exitClean
}
