// Package mcpserver exposes TenantGuard's scan engine over the Model
// Context Protocol (MCP), so an AI agent can invoke it programmatically
// instead of only through a human running the "tenantguard scan" CLI.
//
// This package is a thin protocol adapter: it reuses
// internal/collector, internal/policy, internal/compliance, and
// internal/report exactly as cmd/tenantguard/main.go's "scan" subcommand
// does, and does not duplicate any rule-evaluation or HIPAA-mapping logic.
package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/RudrenduPaul/TenantGuard/internal/collector"
	"github.com/RudrenduPaul/TenantGuard/internal/compliance"
	"github.com/RudrenduPaul/TenantGuard/internal/policy"
	"github.com/RudrenduPaul/TenantGuard/internal/report"
)

// ToolName is the name of the MCP tool that wraps the scan engine.
const ToolName = "scan"

// ScanArgs is the input schema for the "scan" MCP tool. It mirrors the
// "tenantguard scan" CLI flags (--target, --format, --control) so an agent
// driving TenantGuard through MCP gets the same knobs a human gets on the
// command line.
type ScanArgs struct {
	Target  string `json:"target" jsonschema:"absolute or relative path to the deployment configuration directory to scan"`
	Format  string `json:"format,omitempty" jsonschema:"output format: json, sarif, or terminal. Defaults to json, the most useful shape for a calling agent"`
	Control string `json:"control,omitempty" jsonschema:"compliance framework to annotate findings with. Only hipaa is recognized today; an empty value also defaults to hipaa, matching the CLI"`
}

// New builds an MCP server exposing TenantGuard's scan engine as a single
// "scan" tool. Register additional tools by adding more mcp.AddTool calls
// here as TenantGuard's agent-native surface grows.
func New(version string) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "tenantguard",
		Title:   "TenantGuard",
		Version: version,
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name: ToolName,
		Description: "Scan a self-hosted multi-tenant AI-agent deployment's configuration " +
			"directory for tenant-isolation defects (rules TA01-TA16), each mapped to the " +
			"goclaw GitHub issue or pull request that reproduces the same failure mode, with " +
			"an optional (provisional, unverified) HIPAA Sec 164.312 citation. This is the " +
			"same scan engine as the `tenantguard scan` CLI subcommand.",
	}, scanTool)

	return server
}

// Version returns the running binary's module version if it was built with
// embedded module information (e.g. `go install pkg@version`), or "dev"
// otherwise. It populates the MCP server's Implementation.Version.
func Version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

// Run starts the MCP server on the given transport (typically
// &mcp.StdioTransport{} for a CLI subcommand) and blocks until the peer
// disconnects or ctx is canceled.
func Run(ctx context.Context, version string, t mcp.Transport) error {
	return New(version).Run(ctx, t)
}

// scanTool is the handler bound to the "scan" tool. It walks the same
// collector -> policy -> compliance -> report pipeline as
// cmd/tenantguard/main.go's run(), differing only in where the rendered
// report goes: an MCP CallToolResult instead of stdout/a file.
//
// Errors here (bad target, policy load failure, evaluation failure) are
// returned as plain Go errors, which the SDK's generic AddTool wrapper packs
// into CallToolResult.Content with IsError=true -- the MCP-recommended way
// to surface tool-level failures to a calling agent, as opposed to a
// protocol-level error.
func scanTool(ctx context.Context, _ *mcp.CallToolRequest, args ScanArgs) (*mcp.CallToolResult, any, error) {
	if strings.TrimSpace(args.Target) == "" {
		return nil, nil, fmt.Errorf("target is required")
	}

	info, err := os.Stat(args.Target)
	if err != nil {
		return nil, nil, fmt.Errorf("stat target: %w", err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("target must be a directory")
	}

	cfg, err := collector.Collect(args.Target)
	if err != nil {
		return nil, nil, fmt.Errorf("collect config: %w", err)
	}

	evaluator, err := policy.NewEvaluator(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("load policy: %w", err)
	}

	findings, err := evaluator.Evaluate(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("evaluate policy: %w", err)
	}

	// Matches cmd/tenantguard/main.go's run(): hipaa is the default control
	// when none is specified, and it is the only recognized value today.
	if args.Control == "hipaa" || args.Control == "" {
		compliance.Annotate(findings)
	}

	format := args.Format
	if format == "" {
		format = "json"
	}

	var buf bytes.Buffer
	switch format {
	case "sarif":
		if err := report.WriteSARIF(&buf, findings); err != nil {
			return nil, nil, fmt.Errorf("render sarif: %w", err)
		}
	case "terminal":
		report.WriteTerminal(&buf, args.Target, findings)
	default:
		if err := report.WriteJSON(&buf, args.Target, findings); err != nil {
			return nil, nil, fmt.Errorf("render json: %w", err)
		}
	}

	result := &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: buf.String()}},
	}

	// json and sarif are both JSON documents; surface them as
	// StructuredContent too so a calling agent can consume fields directly
	// instead of re-parsing the text block. terminal output is plain text,
	// so it has no structured counterpart.
	if format == "sarif" || format == "json" {
		var structured any
		if err := json.Unmarshal(buf.Bytes(), &structured); err == nil {
			result.StructuredContent = structured
		}
	}

	if len(cfg.Warnings) > 0 {
		var warnings strings.Builder
		warnings.WriteString("collector warnings:\n")
		for _, w := range cfg.Warnings {
			warnings.WriteString("- ")
			warnings.WriteString(w)
			warnings.WriteString("\n")
		}
		result.Content = append([]mcp.Content{&mcp.TextContent{Text: warnings.String()}}, result.Content...)
	}

	return result, nil, nil
}
