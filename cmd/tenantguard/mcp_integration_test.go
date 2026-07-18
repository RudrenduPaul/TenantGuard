package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/RudrenduPaul/TenantGuard/internal/collector"
	"github.com/RudrenduPaul/TenantGuard/internal/compliance"
	"github.com/RudrenduPaul/TenantGuard/internal/demo"
	"github.com/RudrenduPaul/TenantGuard/internal/policy"
	"github.com/RudrenduPaul/TenantGuard/internal/report"
)

// TestMCPEndToEndBinary builds the real tenantguard binary, launches
// `tenantguard mcp` as a subprocess speaking MCP over stdio (via
// mcp.CommandTransport, the same transport a real agent client such as
// Claude Desktop or an MCP-aware IDE would use), connects a real MCP
// client, calls the "scan" tool against the bundled demo fixture, and
// asserts the response matches what the scan engine produces when driven
// directly (collector -> policy -> compliance -> report), byte for byte.
//
// This exercises the actual process boundary — flag parsing for the new
// "mcp" subcommand, stdio framing, and JSON-RPC round-tripping — the same
// bar TestEndToEndBinary already holds the "scan" subcommand to.
func TestMCPEndToEndBinary(t *testing.T) {
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

	demoDir, err := demo.Materialize()
	if err != nil {
		t.Fatalf("demo.Materialize: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(demoDir) })

	// Independently compute what the scan engine itself produces for this
	// exact fixture, entirely outside of MCP, so the assertion below proves
	// the "mcp" subcommand wraps the existing engine rather than
	// reimplementing scan logic.
	want := directEngineJSON(t, demoDir)

	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e-test-client", Version: "v0.0.0"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(binPath, "mcp")}

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect over CommandTransport: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "scan" {
		t.Fatalf("expected exactly one \"scan\" tool, got %+v", tools.Tools)
	}

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "scan",
		Arguments: map[string]any{
			"target": demoDir,
			"format": "json",
		},
	})
	if err != nil {
		t.Fatalf("CallTool(scan): %v", err)
	}
	if res.IsError {
		t.Fatalf("scan tool reported an error over the real subprocess: %+v", res.Content)
	}

	tc, ok := res.Content[len(res.Content)-1].(*mcp.TextContent)
	if !ok {
		t.Fatalf("last content block is %T, want *mcp.TextContent", res.Content[len(res.Content)-1])
	}
	if tc.Text != string(want) {
		t.Errorf("MCP subprocess scan output does not match the engine's direct output.\ngot:\n%s\nwant:\n%s", tc.Text, want)
	}

	// Cross-check against the same known finding count TestEndToEndBinary
	// asserts for the demo fixture's SARIF output (14 FAIL results), since
	// the JSON report is a superset (it also includes PASS findings).
	var parsed struct {
		Summary struct {
			Fail int `json:"fail"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(tc.Text), &parsed); err != nil {
		t.Fatalf("unmarshal scan result: %v", err)
	}
	if parsed.Summary.Fail != 14 {
		t.Errorf("expected 14 FAIL findings against the demo fixture, got %d", parsed.Summary.Fail)
	}
}

// directEngineJSON runs the same collector -> policy -> compliance ->
// report pipeline main.go's runScan uses, independent of MCP, as the
// ground truth for the parity assertion in TestMCPEndToEndBinary.
func directEngineJSON(t *testing.T, target string) []byte {
	t.Helper()
	ctx := context.Background()

	cfg, err := collector.Collect(target)
	if err != nil {
		t.Fatalf("collector.Collect: %v", err)
	}
	evaluator, err := policy.NewEvaluator(ctx)
	if err != nil {
		t.Fatalf("policy.NewEvaluator: %v", err)
	}
	findings, err := evaluator.Evaluate(ctx, cfg)
	if err != nil {
		t.Fatalf("evaluator.Evaluate: %v", err)
	}
	compliance.Annotate(findings)

	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, target, findings); err != nil {
		t.Fatalf("report.WriteJSON: %v", err)
	}
	return buf.Bytes()
}
