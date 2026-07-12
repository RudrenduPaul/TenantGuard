// Package collector walks a target deployment's configuration directory and
// produces a single, merged CollectedConfig document. Every rule in
// internal/policy evaluates against this one document rather than a
// per-file input, because TA03 (cross-agent authorization boundary) must
// correlate CronSchedules against Agents declared in a different file.
package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Location pinpoints where a config entry came from, so a Finding can cite an
// exact file and line rather than "somewhere in your config."
type Location struct {
	File string
	Line int
}

func (l Location) String() string {
	if l.File == "" {
		return "unknown"
	}
	return fmt.Sprintf("%s:%d", l.File, l.Line)
}

// SandboxMount is one entry in a deployment's sandbox.mounts list. TA01 checks
// Path against a per-tenant scoping convention.
type SandboxMount struct {
	Path     string
	Location Location
}

// MCPToolEntry is one entry in a deployment's tools.mcp list. TA02 checks URL
// for SSRF-risk targets that bypass declared validation.
type MCPToolEntry struct {
	URL              string
	ValidatesPrivate bool // true if the entry declares SSRF validation on private/loopback targets
	Location         Location
}

// AgentEntry is one declared agent, scoped to a tenant. TA03 cross-references
// this list against CronBinding.TargetAgent.
type AgentEntry struct {
	Name     string
	Tenant   string
	Location Location
}

// CronBinding is one scheduled job. TA03 checks that TargetAgent belongs to
// the same Tenant that declared the binding.
type CronBinding struct {
	Tenant      string
	TargetAgent string
	Location    Location
}

// ExecToolEntry is one entry in a deployment's tools.exec list. TA04 checks
// EnvPolicy for indirect env-read paths; TA05 checks Approvals for
// basename-only allow-always entries.
type ExecToolEntry struct {
	Name      string
	EnvPolicy EnvPolicy
	Approvals []ApprovalEntry
	Location  Location
}

// EnvPolicy describes what an exec tool is allowed to read from the process
// environment, and whether indirect reads (e.g. a shell invoking `jq $ENV`)
// are covered by the same denylist as direct reads.
type EnvPolicy struct {
	DenyDirectEnvDump   bool
	DenyIndirectEnvRead bool
	// AllowChainExec mirrors goclaw PR#1033's per-CLI allow_chain_exec: when
	// true, credential env vars are injected into and visible to every
	// command in a shell operator chain (e.g. `which gh && gh pr list`),
	// not just the credentialed binary itself.
	AllowChainExec bool
}

// ApprovalEntry is one "allow-always" rule for an exec tool invocation.
type ApprovalEntry struct {
	Basename   string
	PathScoped bool // true if the approval is scoped to a specific full path, not basename alone
	Location   Location
}

// CollectedConfig is the single merged document every Rego policy evaluates
// against. It is built once per scan from every recognized config file under
// the target directory.
type CollectedConfig struct {
	SourceDeployment string
	Sandboxes        []SandboxMount
	MCPTools         []MCPToolEntry
	CronSchedules    []CronBinding
	Agents           []AgentEntry
	ExecTools        []ExecToolEntry
	// Warnings holds one message per config file containing a field this
	// collector doesn't recognize (e.g. a newer goclaw schema). These are
	// schema-level checks, not version-gated — the scan proceeds rather than
	// blocking, but the warning is surfaced, never silently dropped.
	Warnings []string
}

// rawDeploymentFile is the on-disk shape of one config file. A real deployment
// may split these sections across several files; Collect merges all of them.
type rawDeploymentFile struct {
	Sandbox struct {
		Mounts []struct {
			Path string `yaml:"path"`
		} `yaml:"mounts"`
	} `yaml:"sandbox"`
	Tools struct {
		MCP []struct {
			URL              string `yaml:"url"`
			ValidatesPrivate bool   `yaml:"validates_private"`
		} `yaml:"mcp"`
		Exec []struct {
			Name      string `yaml:"name"`
			EnvPolicy struct {
				DenyDirectEnvDump   bool `yaml:"deny_direct_env_dump"`
				DenyIndirectEnvRead bool `yaml:"deny_indirect_env_read"`
				AllowChainExec      bool `yaml:"allow_chain_exec"`
			} `yaml:"env_policy"`
			Approvals []struct {
				Basename   string `yaml:"basename"`
				PathScoped bool   `yaml:"path_scoped"`
			} `yaml:"approvals"`
		} `yaml:"exec"`
	} `yaml:"tools"`
	Schedules struct {
		Cron []struct {
			Tenant      string `yaml:"tenant"`
			TargetAgent string `yaml:"target_agent"`
		} `yaml:"cron"`
	} `yaml:"schedules"`
	Agents []struct {
		Name   string `yaml:"name"`
		Tenant string `yaml:"tenant"`
	} `yaml:"agents"`
}

// Collect walks target (a directory) and merges every *.yml/*.yaml file it
// finds into one CollectedConfig. It fails loudly — never silently skips a
// file it can't parse, and never returns a clean empty result for a target
// that had nothing to scan.
func Collect(target string) (*CollectedConfig, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("target %q: %w", target, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("target %q must be a directory", target)
	}

	cfg := &CollectedConfig{SourceDeployment: target}
	filesSeen := 0

	err = filepath.WalkDir(target, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		filesSeen++
		return mergeFile(cfg, path)
	})
	if err != nil {
		return nil, err
	}

	if filesSeen == 0 {
		return nil, &ErrNoConfigFound{Target: target}
	}

	return cfg, nil
}

func mergeFile(cfg *CollectedConfig, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	// Decode three ways: (1) strict, only to detect fields this collector
	// doesn't recognize and turn that into a warning, never a hard failure;
	// (2) normal, into a typed struct for values; (3) into a Node tree so
	// every list entry can carry its real source line, not just the file.
	var strictProbe rawDeploymentFile
	strictDec := yaml.NewDecoder(strings.NewReader(string(data)))
	strictDec.KnownFields(true)
	if err := strictDec.Decode(&strictProbe); err != nil {
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("%s: unrecognized field(s), possibly a newer goclaw schema: %v", path, err))
	}

	var raw rawDeploymentFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return &ErrMalformedConfig{File: path, Line: 0, Err: err}
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return &ErrMalformedConfig{File: path, Line: 0, Err: err}
	}

	lines := lineIndex(&root)

	for i, m := range raw.Sandbox.Mounts {
		cfg.Sandboxes = append(cfg.Sandboxes, SandboxMount{
			Path:     m.Path,
			Location: Location{File: path, Line: lines.lookup("sandbox.mounts", i)},
		})
	}
	for i, m := range raw.Tools.MCP {
		cfg.MCPTools = append(cfg.MCPTools, MCPToolEntry{
			URL:              m.URL,
			ValidatesPrivate: m.ValidatesPrivate,
			Location:         Location{File: path, Line: lines.lookup("tools.mcp", i)},
		})
	}
	for i, e := range raw.Tools.Exec {
		entry := ExecToolEntry{
			Name: e.Name,
			EnvPolicy: EnvPolicy{
				DenyDirectEnvDump:   e.EnvPolicy.DenyDirectEnvDump,
				DenyIndirectEnvRead: e.EnvPolicy.DenyIndirectEnvRead,
				AllowChainExec:      e.EnvPolicy.AllowChainExec,
			},
			Location: Location{File: path, Line: lines.lookup("tools.exec", i)},
		}
		for j, a := range e.Approvals {
			entry.Approvals = append(entry.Approvals, ApprovalEntry{
				Basename:   a.Basename,
				PathScoped: a.PathScoped,
				Location:   Location{File: path, Line: lines.lookup(fmt.Sprintf("tools.exec.%d.approvals", i), j)},
			})
		}
		cfg.ExecTools = append(cfg.ExecTools, entry)
	}
	for i, c := range raw.Schedules.Cron {
		cfg.CronSchedules = append(cfg.CronSchedules, CronBinding{
			Tenant:      c.Tenant,
			TargetAgent: c.TargetAgent,
			Location:    Location{File: path, Line: lines.lookup("schedules.cron", i)},
		})
	}
	for i, a := range raw.Agents {
		cfg.Agents = append(cfg.Agents, AgentEntry{
			Name:     a.Name,
			Tenant:   a.Tenant,
			Location: Location{File: path, Line: lines.lookup("agents", i)},
		})
	}

	return nil
}
