// Package collector walks a target deployment's configuration directory and
// produces a single, merged CollectedConfig document. Every rule in
// internal/policy evaluates against this one document rather than a
// per-file input, because TA03 (cross-agent authorization boundary) must
// correlate CronSchedules against Agents declared in a different file.
package collector

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

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
// Path against a per-tenant scoping convention, or accepts ScopedPerTenant as
// a second, independent signal — an explicit declaration (by a human today,
// or a future runtime/source collector) that the mount is actually scoped
// per tenant even though Path itself doesn't carry the ${TENANT_ID}
// convention's placeholder literal (e.g. a mount path computed by real Go
// code will never contain that literal template token).
type SandboxMount struct {
	Path            string
	ScopedPerTenant bool
	Location        Location
}

// MCPToolEntry is one entry in a deployment's tools.mcp list. TA02 checks URL
// for SSRF-risk targets that bypass declared validation.
type MCPToolEntry struct {
	URL string

	// ValidatesPrivate is true if the entry declares that an SSRF validator
	// ran against this URL at all. As of the DNS-rebinding discussion on
	// goclaw#1070 (@m13v, @linkdao), this alone is no longer sufficient for
	// TA02 to treat a private-target tool as safe — see PinsResolvedIP.
	ValidatesPrivate bool

	// PinsResolvedIP is true if the declared validator resolves the
	// hostname ONCE and pins the resulting IP for the actual outbound
	// connection, rather than trusting the hostname again at connect time.
	// Without pinning, an attacker who controls DNS for an
	// already-validated hostname can flip the A record after validation
	// and still reach a private/metadata target — DNS rebinding / TOCTOU.
	PinsResolvedIP bool

	// ExplicitlyAllowedHost is true if this tool's host is explicitly
	// allowlisted for local/private use — either declared directly in
	// TenantGuard's own YAML (tools.mcp[].allowed_private_host), or
	// auto-enriched by CollectFromGoclawEnv from goclaw's real
	// GOCLAW_MCP_ALLOWED_HOSTS env var (goclaw#1248). This is the "Option A"
	// escape hatch requested directly in the goclaw#1070 issue thread.
	ExplicitlyAllowedHost bool

	// ResolvedIPs is the best-effort result of resolving URL's hostname to
	// IP address(es) ONCE at collection time — never at scan/rego-eval
	// time, so a scan stays deterministic and offline-safe once collection
	// has finished. Empty if the URL already embeds a literal IP that
	// doesn't need resolving, or if resolution failed; a failure never
	// fails the whole scan, it only adds a CollectedConfig.Warnings entry.
	// This is what lets TA02 catch a hostname like host.docker.internal —
	// the exact repro in goclaw#1070 — which resolves to a private IP but
	// has no private-looking substring in the URL text itself.
	ResolvedIPs []string

	Location Location
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
}

// ApprovalEntry is one "allow-always" rule for an exec tool invocation.
type ApprovalEntry struct {
	Basename   string
	PathScoped bool // true if the approval is scoped to a specific full path, not basename alone
	Location   Location
}

// ProviderEntry is one entry in a deployment's providers list. TA08 checks
// OAuthTokenStorageEncryption for a declared strong-encryption algorithm on
// stored OAuth/credential tokens.
type ProviderEntry struct {
	Name                        string
	OAuthTokenStorageEncryption string
	Location                    Location
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
	Providers        []ProviderEntry
	// Warnings holds one message per config file containing a field this
	// collector doesn't recognize (e.g. a newer goclaw schema), plus any
	// per-entry best-effort enrichment failure (e.g. an MCP tool hostname
	// that could not be resolved). These are non-fatal — the scan proceeds
	// rather than blocking, but the warning is surfaced, never silently
	// dropped.
	Warnings []string
}

// rawDeploymentFile is the on-disk shape of one config file. A real deployment
// may split these sections across several files; Collect merges all of them.
type rawDeploymentFile struct {
	Sandbox struct {
		Mounts []struct {
			Path            string `yaml:"path"`
			ScopedPerTenant bool   `yaml:"scoped_per_tenant"`
		} `yaml:"mounts"`
	} `yaml:"sandbox"`
	Tools struct {
		MCP []struct {
			URL                string `yaml:"url"`
			ValidatesPrivate   bool   `yaml:"validates_private"`
			PinsResolvedIP     bool   `yaml:"pins_resolved_ip"`
			AllowedPrivateHost bool   `yaml:"allowed_private_host"`
		} `yaml:"mcp"`
		Exec []struct {
			Name      string `yaml:"name"`
			EnvPolicy struct {
				DenyDirectEnvDump   bool `yaml:"deny_direct_env_dump"`
				DenyIndirectEnvRead bool `yaml:"deny_indirect_env_read"`
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
	Providers []struct {
		Name  string `yaml:"name"`
		OAuth struct {
			TokenStorage struct {
				Encryption string `yaml:"encryption"`
			} `yaml:"token_storage"`
		} `yaml:"oauth"`
	} `yaml:"providers"`
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
			Path:            m.Path,
			ScopedPerTenant: m.ScopedPerTenant,
			Location:        Location{File: path, Line: lines.lookup("sandbox.mounts", i)},
		})
	}
	for i, m := range raw.Tools.MCP {
		cfg.MCPTools = append(cfg.MCPTools, MCPToolEntry{
			URL:                   m.URL,
			ValidatesPrivate:      m.ValidatesPrivate,
			PinsResolvedIP:        m.PinsResolvedIP,
			ExplicitlyAllowedHost: m.AllowedPrivateHost,
			ResolvedIPs:           resolveMCPHost(cfg, path, m.URL),
			Location:              Location{File: path, Line: lines.lookup("tools.mcp", i)},
		})
	}
	for i, e := range raw.Tools.Exec {
		entry := ExecToolEntry{
			Name: e.Name,
			EnvPolicy: EnvPolicy{
				DenyDirectEnvDump:   e.EnvPolicy.DenyDirectEnvDump,
				DenyIndirectEnvRead: e.EnvPolicy.DenyIndirectEnvRead,
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
	for i, p := range raw.Providers {
		cfg.Providers = append(cfg.Providers, ProviderEntry{
			Name:                        p.Name,
			OAuthTokenStorageEncryption: p.OAuth.TokenStorage.Encryption,
			Location:                    Location{File: path, Line: lines.lookup("providers", i)},
		})
	}

	return nil
}

// LookupHost resolves an MCP tool URL's hostname to its IP address(es) at
// collection time. It is a package-level var — not a direct call to
// net.LookupHost — purely so tests can substitute a deterministic fake
// resolver instead of depending on live DNS (see the host.docker.internal
// goclaw#1070 repro exercised in the test suite). Bounded to a short
// timeout so a single unresolvable hostname can't hang an entire scan.
var LookupHost = func(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupHost(ctx, host)
}

// resolveMCPHost extracts rawURL's hostname and resolves it via LookupHost,
// once, at collection time — see MCPToolEntry.ResolvedIPs. A literal IP in
// rawURL (e.g. http://127.0.0.1/...) resolves immediately with no network
// call, since Go's resolver short-circuits IP literals. Resolution failure
// is reported as a warning, never a fatal collection error: a deployment's
// MCP tool config should still be collectible even if this machine
// currently can't reach DNS for one of its hosts.
func resolveMCPHost(cfg *CollectedConfig, path, rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	ips, err := LookupHost(u.Hostname())
	if err != nil {
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("%s: could not resolve MCP tool hostname %q: %v", path, u.Hostname(), err))
		return nil
	}
	return ips
}

// CollectFromGoclawEnv is an additive, best-effort enrichment step run
// separately from Collect() — never wired into it automatically, so the
// existing YAML-only collection path keeps working exactly as-is for
// backward compatibility. It reads goclaw's own GOCLAW_MCP_ALLOWED_HOSTS
// environment variable — a comma-separated list of hostnames goclaw's real
// gateway config wires into mcp.SetAllowedHosts, see goclaw PR #1248 — and
// flips ExplicitlyAllowedHost to true on any already-collected MCPToolEntry
// whose URL hostname appears in that list (case-insensitive, matching PR
// #1248's own trim+lowercase normalization). This lets TA02 recognize a
// real goclaw deployment's actual opt-in allowlist instead of relying
// solely on TenantGuard's own bespoke YAML schema, closing the "raw capture
// needing interpretation" gap called out for goclaw#1248.
//
// A live read of goclaw's DB-backed MCP server registration table is out of
// scope for this pass — it needs a running goclaw instance plus a DB
// driver; this covers the env-var adapter only.
func CollectFromGoclawEnv(cfg *CollectedConfig) error {
	raw := strings.TrimSpace(os.Getenv("GOCLAW_MCP_ALLOWED_HOSTS"))
	if raw == "" {
		return nil
	}
	allowed := map[string]bool{}
	for _, h := range strings.Split(raw, ",") {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			allowed[h] = true
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	for i, m := range cfg.MCPTools {
		u, err := url.Parse(m.URL)
		if err != nil {
			continue
		}
		if host := strings.ToLower(u.Hostname()); host != "" && allowed[host] {
			cfg.MCPTools[i].ExplicitlyAllowedHost = true
		}
	}
	return nil
}
