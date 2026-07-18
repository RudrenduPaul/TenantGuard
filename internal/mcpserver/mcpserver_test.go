package mcpserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/RudrenduPaul/TenantGuard/internal/collector"
	"github.com/RudrenduPaul/TenantGuard/internal/compliance"
	"github.com/RudrenduPaul/TenantGuard/internal/demo"
	"github.com/RudrenduPaul/TenantGuard/internal/mcpserver"
	"github.com/RudrenduPaul/TenantGuard/internal/policy"
	"github.com/RudrenduPaul/TenantGuard/internal/report"
)

// connect wires an in-process client to a fresh mcpserver.New("test")
// server over mcp.NewInMemoryTransports, and registers cleanup to close
// both ends. It returns a ready-to-use ClientSession.
func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	server := mcpserver.New("test")
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0.0.0"}, nil)

	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	t.Cleanup(func() { _ = serverSession.Wait() })

	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })

	return clientSession
}

// referenceEngineOutput runs the exact collector -> policy -> compliance ->
// report pipeline that cmd/tenantguard/main.go's "scan" subcommand and the
// mcpserver "scan" tool both wrap, independently of the MCP layer, so tests
// can assert the MCP tool's response is byte-identical to what the engine
// itself produces for the same target and control.
func referenceEngineOutput(t *testing.T, target, control string) []byte {
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

	if control == "hipaa" || control == "" {
		compliance.Annotate(findings)
	}

	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, target, findings); err != nil {
		t.Fatalf("report.WriteJSON: %v", err)
	}
	return buf.Bytes()
}

func callScan(t *testing.T, session *mcp.ClientSession, args mcpserver.ScanArgs) *mcp.CallToolResult {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      mcpserver.ToolName,
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool(%q): %v", mcpserver.ToolName, err)
	}
	return res
}

func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatalf("result has no content blocks")
	}
	tc, ok := res.Content[len(res.Content)-1].(*mcp.TextContent)
	if !ok {
		t.Fatalf("last content block is %T, want *mcp.TextContent", res.Content[len(res.Content)-1])
	}
	return tc.Text
}

// TestListTools verifies the server advertises exactly the "scan" tool an
// agent client would discover via tools/list.
func TestListTools(t *testing.T) {
	session := connect(t)
	res, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(res.Tools) != 1 {
		t.Fatalf("got %d tools, want 1: %+v", len(res.Tools), res.Tools)
	}
	if res.Tools[0].Name != mcpserver.ToolName {
		t.Errorf("tool name = %q, want %q", res.Tools[0].Name, mcpserver.ToolName)
	}
	if res.Tools[0].Description == "" {
		t.Errorf("tool description is empty")
	}
}

// TestScanTool_JSONMatchesEngine is the core parity test: it starts the MCP
// server, calls the "scan" tool against the bundled demo fixture (known
// TA01-TA16 violations), and asserts the response is byte-identical to what
// internal/collector + internal/policy + internal/compliance +
// internal/report produce when driven directly, outside of MCP entirely —
// proving the tool wraps the existing engine rather than reimplementing it.
func TestScanTool_JSONMatchesEngine(t *testing.T) {
	demoDir, err := demo.Materialize()
	if err != nil {
		t.Fatalf("demo.Materialize: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(demoDir) })

	want := referenceEngineOutput(t, demoDir, "")

	session := connect(t)
	res := callScan(t, session, mcpserver.ScanArgs{Target: demoDir, Format: "json"})
	if res.IsError {
		t.Fatalf("scan tool reported an error: %s", textOf(t, res))
	}

	got := textOf(t, res)
	if got != string(want) {
		t.Errorf("MCP scan tool JSON output does not match the engine's direct output.\ngot:\n%s\nwant:\n%s", got, want)
	}

	if res.StructuredContent == nil {
		t.Fatalf("expected StructuredContent to be populated for format=json")
	}
	var wantParsed, gotParsed any
	if err := json.Unmarshal(want, &wantParsed); err != nil {
		t.Fatalf("unmarshal reference output: %v", err)
	}
	gotBytes, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal StructuredContent: %v", err)
	}
	if err := json.Unmarshal(gotBytes, &gotParsed); err != nil {
		t.Fatalf("unmarshal StructuredContent: %v", err)
	}
	wantBytes, _ := json.Marshal(wantParsed)
	gotBytesNorm, _ := json.Marshal(gotParsed)
	if string(wantBytes) != string(gotBytesNorm) {
		t.Errorf("StructuredContent does not match the reference report:\ngot:  %s\nwant: %s", gotBytesNorm, wantBytes)
	}
}

// TestScanTool_DefaultFormatIsJSON checks that omitting --format (unlike
// the CLI, which defaults to terminal) gives an agent caller structured
// JSON by default, since that is the shape a program can actually parse.
func TestScanTool_DefaultFormatIsJSON(t *testing.T) {
	demoDir, err := demo.Materialize()
	if err != nil {
		t.Fatalf("demo.Materialize: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(demoDir) })

	session := connect(t)
	res := callScan(t, session, mcpserver.ScanArgs{Target: demoDir})
	if res.IsError {
		t.Fatalf("scan tool reported an error: %s", textOf(t, res))
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(textOf(t, res)), &parsed); err != nil {
		t.Fatalf("default-format output is not valid JSON: %v\noutput: %s", err, textOf(t, res))
	}
	if _, ok := parsed["findings"]; !ok {
		t.Errorf("expected a top-level \"findings\" field in default-format output, got %v", parsed)
	}
}

// TestScanTool_SARIF asserts format=sarif produces the same SARIF document
// internal/report.WriteSARIF produces directly.
func TestScanTool_SARIF(t *testing.T) {
	demoDir, err := demo.Materialize()
	if err != nil {
		t.Fatalf("demo.Materialize: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(demoDir) })

	ctx := context.Background()
	cfg, err := collector.Collect(demoDir)
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
	var want bytes.Buffer
	if err := report.WriteSARIF(&want, findings); err != nil {
		t.Fatalf("report.WriteSARIF: %v", err)
	}

	session := connect(t)
	res := callScan(t, session, mcpserver.ScanArgs{Target: demoDir, Format: "sarif"})
	if res.IsError {
		t.Fatalf("scan tool reported an error: %s", textOf(t, res))
	}
	if got := textOf(t, res); got != want.String() {
		t.Errorf("MCP scan tool SARIF output does not match report.WriteSARIF's direct output.\ngot:\n%s\nwant:\n%s", got, want.String())
	}
	if res.StructuredContent == nil {
		t.Errorf("expected StructuredContent to be populated for format=sarif")
	}
}

// TestScanTool_CleanTargetHasNoFailures runs against the known-clean
// fixture under cmd/tenantguard/testdata/clean and checks the JSON summary
// reports zero failures, mirroring TestCleanTargetExitsZero in
// cmd/tenantguard/main_test.go for the CLI path.
func TestScanTool_CleanTargetHasNoFailures(t *testing.T) {
	cleanDir := filepath.Join("..", "..", "cmd", "tenantguard", "testdata", "clean")
	session := connect(t)
	res := callScan(t, session, mcpserver.ScanArgs{Target: cleanDir, Format: "json"})
	if res.IsError {
		t.Fatalf("scan tool reported an error: %s", textOf(t, res))
	}

	var parsed struct {
		Summary struct {
			Fail int `json:"fail"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(textOf(t, res)), &parsed); err != nil {
		t.Fatalf("unmarshal scan result: %v", err)
	}
	if parsed.Summary.Fail != 0 {
		t.Errorf("expected 0 failures against the clean fixture, got %d", parsed.Summary.Fail)
	}
}

// TestScanTool_MissingTarget checks that an empty target is reported as a
// tool-level error (IsError=true, error text in Content), not a protocol
// error, per the MCP spec's guidance for tool execution failures.
func TestScanTool_MissingTarget(t *testing.T) {
	session := connect(t)
	res := callScan(t, session, mcpserver.ScanArgs{})
	if !res.IsError {
		t.Fatalf("expected IsError=true for a missing target, got a clean result: %s", textOf(t, res))
	}
	if !strings.Contains(textOf(t, res), "target is required") {
		t.Errorf("expected a clear target-required error, got %q", textOf(t, res))
	}
}

// TestScanTool_TargetNotDirectory checks that pointing --target at a file
// (not a directory) is reported the same way the CLI reports it.
func TestScanTool_TargetNotDirectory(t *testing.T) {
	session := connect(t)
	res := callScan(t, session, mcpserver.ScanArgs{Target: "mcpserver_test.go"})
	if !res.IsError {
		t.Fatalf("expected IsError=true for a non-directory target, got a clean result: %s", textOf(t, res))
	}
	if !strings.Contains(textOf(t, res), "must be a directory") {
		t.Errorf("expected a target-must-be-directory error, got %q", textOf(t, res))
	}
}

// TestScanTool_UnknownTarget checks that a target that does not exist is
// reported as a tool-level error rather than crashing the server.
func TestScanTool_UnknownTarget(t *testing.T) {
	session := connect(t)
	res := callScan(t, session, mcpserver.ScanArgs{Target: filepath.Join(t.TempDir(), "does-not-exist")})
	if !res.IsError {
		t.Fatalf("expected IsError=true for a nonexistent target, got a clean result: %s", textOf(t, res))
	}
}

// TestVersion checks that Version() never returns an empty string, whether
// or not the test binary carries embedded module version information.
func TestVersion(t *testing.T) {
	if v := mcpserver.Version(); v == "" {
		t.Errorf("Version() returned an empty string")
	}
}
