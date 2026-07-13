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
// Path against a per-tenant scoping convention. TA07 checks the
// container-privilege fields below (User, EnvMode, TmpfsFlags, CapAdd)
// against a hardening baseline: root-as-default, host-environment
// passthrough, tmpfs mounts missing exec-prevention flags, and excess Linux
// capabilities all give a compromised sandboxed process an easy escape
// path.
type SandboxMount struct {
	Path            string
	ScopedPerTenant bool
	User            string
	EnvMode         string
	TmpfsFlags      []string
	CapAdd          []string
	Location        Location
}

// BrowserConfig is the deployment-level declaration of which browser/
// headless-automation backend a deployment uses (Backend) and how it claims
// to isolate tenants on that backend (IsolationMode). Unlike ResourceProfile
// (a per-entry list of profile storage paths), both fields are single,
// deployment-scoped declarations -- TA14 checks them once per scan, not once
// per profile index.
//
// This closes a gap where a backend whose isolation guarantee is
// architectural rather than path-based (e.g. goclaw#1028's Lightpanda
// backend, whose author describes isolation as "implicit -- every
// connection gets a fresh browser") declares zero resources.browser.profiles
// entries. Before this field existed, that meant TA14 had literally nothing
// to iterate and silently produced zero findings -- not because isolation
// had been verified, but because TA14 had no declared fact to check at all.
// Declaring backend_isolation_mode: stateless gives TenantGuard an explicit
// claim it can check (and, going forward, a place to grow a real
// runtime/architectural verification against), instead of a silent
// pass-by-omission.
type BrowserConfig struct {
	// BackendDeclared is true only if some scanned config file actually
	// declared resources.browser.backend (even as an empty string) --
	// this is the signal that browser automation is in play at all, which
	// is what obligates a deployment to also declare IsolationMode.
	BackendDeclared bool
	Backend         string
	// IsolationModeDeclared is true only if some scanned config file
	// actually declared resources.browser.backend_isolation_mode. A
	// deployment that declares Backend but never declares this is a TA14
	// FAIL: an undeclared isolation posture for an in-use browser backend,
	// not a silent PASS.
	IsolationModeDeclared bool
	// IsolationMode is "scoped_path" or "stateless" when declared. Any
	// other declared value is treated as unrecognized (still FAIL) by
	// ta14.rego, so a typo can't accidentally short-circuit the check.
	IsolationMode string
	Location      Location
}

// ResourceProfile is one entry in a deployment's resources.browser.profiles
// list. TA14 checks Path against the same per-tenant scoping convention TA01
// applies to sandbox mounts, but for browser/container profile storage
// paths — a resource category goclaw's own tenant-isolation defects (PR
// nextlevelbuilder/goclaw#778, "cross-agent browser profile isolation fix")
// show is a genuine gap when left unscoped. This scoped_path check only
// applies when BrowserConfig.IsolationMode is "scoped_path" (or undeclared,
// the legacy default) -- a deployment that declares "stateless" is claiming
// a different, connection-level isolation mechanism instead (see
// BrowserConfig's doc comment).
type ResourceProfile struct {
	Path     string
	Location Location

	// User is the container/sandbox run-as user. Empty or "root" means the
	// sandbox defaults to running as root (goclaw#1014, goclaw#1015).
	User string
	// EnvMode declares how the sandbox's process environment is populated.
	// "inherit_host" passes through the full host environment, leaking
	// host credentials/PATH into the sandboxed process (goclaw#1014,
	// goclaw#1015); "isolated" or "explicit_allowlist" are the hardened
	// options.
	EnvMode string
	// TmpfsFlags lists the mount flags applied to the sandbox's tmpfs
	// mounts. Must include noexec, nosuid, and nodev to stop tmpfs being
	// used to bypass exec/setuid controls (goclaw#728).
	TmpfsFlags []string
	// CapAdd lists Linux capabilities added beyond the container runtime's
	// default set. Capabilities such as SETUID, SETGID, and CHOWN allow
	// privilege escalation out of the sandbox and should not be added
	// (goclaw#524).
	CapAdd []string
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
// this list against CronBinding.TargetAgent. TA10 checks the two override
// flags below: goclaw PR #145 found per-agent DB settings (restrict_to_
// workspace, sandbox config, among others) were silently ignored at runtime
// because tool config was baked in at process startup instead of resolved
// per-agent. TenantGuard can't see that runtime bug from static YAML, but it
// can flag deployments whose config layer never even declares a per-agent
// override for these settings in the first place, and so is silently
// inheriting an undeclared global default.
type AgentEntry struct {
	Name     string
	Tenant   string
	Location Location
	// HasWorkspaceRestrictionOverride is true if this agent's YAML entry
	// declares agents[].overrides.workspace_restriction explicitly (any
	// value, including false) rather than leaving it undeclared.
	HasWorkspaceRestrictionOverride bool
	// HasSandboxConfigOverride is true if this agent's YAML entry declares a
	// non-empty agents[].overrides.sandbox_config block.
	HasSandboxConfigOverride bool
}

// CronBinding is one scheduled job. TA03 checks that TargetAgent belongs to
// the same Tenant that declared the binding. TA06 checks CreatorCaptured --
// whether the store layer captures the human creator's sender/role identity
// at cron-create time so it can be replayed at fire time (see goclaw#1129).
type CronBinding struct {
	Tenant          string
	TargetAgent     string
	CreatorCaptured bool
	Location        Location
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

// ProviderEntry is one entry in a deployment's providers list. TA08 checks
// OAuthTokenStorageEncryption for a declared strong-encryption algorithm on
// stored OAuth/credential tokens.
type ProviderEntry struct {
	Name                        string
	OAuthTokenStorageEncryption string
	Location                    Location
}

// OwnerConfig captures a deployment's owner/sysadmin recovery guarantees.
// Unlike the other sections, this is deployment-level, not a list of
// entries: TA12 asks whether the deployment as a whole guarantees (a) a
// valid gateway-token-authenticated `system` account is always treated as
// emergency sysadmin, and (b) a recovery/reset command is declared. See
// goclaw#954, a maintainer-acknowledged CRITICAL design gap describing
// owner/sysadmin configuration with no guaranteed recovery path.
type OwnerConfig struct {
	OwnerIDs           []string
	GatewayTokenEnv    string
	HasRecoveryCommand bool
	// Declared is true only if some scanned config file actually contained
	// an owner: section (even an empty one). This lets TA12 distinguish
	// "declared but empty" from "never declared at all" for citation
	// purposes, while still treating both as FAIL-worthy — an absent owner
	// section guarantees nothing, which is exactly the gap goclaw#954
	// describes.
	Declared bool
	Location Location
}

// BridgeConfig is the deployment-level MCP/CLI bridge section. Unlike the
// other sections above, it is a single, deployment-scoped declaration, not a
// list of entries — TA13 checks it as one thing per scan, not once per
// index. Declared is false when no config file in the target declared a
// bridge: section at all, which TA13 treats identically to an explicit
// false (see collector.Collect's doc comment: fail loudly, never scan clean
// by default).
type BridgeConfig struct {
	Declared             bool
	HMACEnabled          bool
	ContextHeadersSigned bool
	Location             Location
}

// ChannelInstance is one declared messaging-channel instance (e.g. a
// WhatsApp, Slack, or Telegram connection), scoped to a tenant. TA11 checks
// that no two channel_instances entries share the same DeviceSessionID while
// declaring different Tenant values — goclaw#1064/#1065 showed that sharing
// one device-session row (e.g. one whatsmeow device) across channel
// instances lets a second tenant's channel silently connect as the first
// tenant's already-paired account. TA15 checks ReloadStrategy — goclaw#1147
// showed that InstanceLoader.Reload() does a destructive full stop/restart
// of every running channel instance on any single channel_instance
// create/update/delete, because the reload event carries no information
// about which instance changed and there is no fingerprint/diff step, so one
// tenant's channel CRUD interrupts every other tenant's in-progress
// conversations across every channel.
type ChannelInstance struct {
	Channel         string
	Tenant          string
	DeviceSessionID string
	// ReloadStrategy is the deployment's declared reload behavior for this
	// channel instance, e.g. "differential" or "full". TA15 fails closed on
	// anything other than "differential" (including an undeclared/empty
	// value), matching this collector's fail-loudly philosophy.
	ReloadStrategy string
	Location       Location
}

// CollectedConfig is the single merged document every Rego policy evaluates
// against. It is built once per scan from every recognized config file under
// the target directory.
type CollectedConfig struct {
	SourceDeployment string
	Sandboxes        []SandboxMount
	// SandboxOnUnavailable is the deployment-level (not per-entry) declared
	// posture for sandbox.on_unavailable, e.g. "fail_closed". TA09 checks
	// this directly rather than through the per-index list pattern the other
	// rules use, since it is a single scalar setting for the whole
	// deployment, not one entry per array index.
	SandboxOnUnavailable string
	// SandboxOnUnavailableDeclared is false if no config file under the
	// target ever declared sandbox.on_unavailable at all. TA09 treats an
	// undeclared value as a real gap (FAIL), never a silent PASS — matching
	// this collector's own fail-loudly philosophy documented below.
	SandboxOnUnavailableDeclared bool
	// SandboxOnUnavailableLocation is only meaningful when
	// SandboxOnUnavailableDeclared is true; there is no line to cite for a
	// key that was never written.
	SandboxOnUnavailableLocation Location
	MCPTools                     []MCPToolEntry
	CronSchedules                []CronBinding
	Agents                       []AgentEntry
	ExecTools                    []ExecToolEntry
	Providers                    []ProviderEntry
	// Owner captures the deployment's owner/sysadmin recovery guarantees.
	// TA12 evaluates this as a single deployment-level Finding, not one per
	// array entry, since it describes a global invariant rather than a list.
	Owner            OwnerConfig
	Bridge           BridgeConfig
	ResourceProfiles []ResourceProfile
	// Browser is the deployment-level backend/isolation-mode declaration
	// TA14 checks alongside the per-index ResourceProfiles list -- see
	// BrowserConfig's doc comment.
	Browser          BrowserConfig
	ChannelInstances []ChannelInstance
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
			Path            string   `yaml:"path"`
			ScopedPerTenant bool     `yaml:"scoped_per_tenant"`
			User            string   `yaml:"user"`
			EnvMode         string   `yaml:"env_mode"`
			TmpfsFlags      []string `yaml:"tmpfs_flags"`
			CapAdd          []string `yaml:"cap_add"`
		} `yaml:"mounts"`
		// OnUnavailable is the deployment's declared fail posture for a
		// Docker sandbox that becomes unavailable at runtime (daemon down,
		// binary missing). Reproduces goclaw#246, which hardened the
		// runtime to fail closed instead of silently falling back to
		// unsandboxed host execution; TA09 checks that a deployment has
		// actually declared that posture.
		OnUnavailable string `yaml:"on_unavailable"`
	} `yaml:"sandbox"`
	Resources struct {
		Browser struct {
			// Backend names the browser/headless-automation backend in use,
			// e.g. "chrome" or "lightpanda" (goclaw's own
			// GOCLAW_BROWSER_BACKEND values, goclaw#1028). Only used to
			// detect that browser automation is declared at all -- TA14
			// does not judge backend choice itself.
			Backend string `yaml:"backend"`
			// BackendIsolationMode is the deployment's declared
			// tenant-isolation posture for Backend: "scoped_path" (the
			// legacy convention -- every profiles[].path must embed
			// ${TENANT_ID}) or "stateless" (isolation is claimed to be
			// architectural, e.g. a fresh browser per CDP connection, so no
			// persistent scannable path is expected to exist at all).
			BackendIsolationMode string `yaml:"backend_isolation_mode"`
			Profiles             []struct {
				Path string `yaml:"path"`
			} `yaml:"profiles"`
		} `yaml:"browser"`
	} `yaml:"resources"`
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
			Tenant                  string `yaml:"tenant"`
			TargetAgent             string `yaml:"target_agent"`
			CapturesCreatorIdentity bool   `yaml:"captures_creator_identity"`
		} `yaml:"cron"`
	} `yaml:"schedules"`
	Agents []struct {
		Name      string `yaml:"name"`
		Tenant    string `yaml:"tenant"`
		Overrides *struct {
			WorkspaceRestriction *bool          `yaml:"workspace_restriction"`
			SandboxConfig        map[string]any `yaml:"sandbox_config"`
		} `yaml:"overrides"`
	} `yaml:"agents"`
	Providers []struct {
		Name  string `yaml:"name"`
		OAuth struct {
			TokenStorage struct {
				Encryption string `yaml:"encryption"`
			} `yaml:"token_storage"`
		} `yaml:"oauth"`
	} `yaml:"providers"`
	// Owner is a pointer so yaml.v3 leaves it nil when no owner: section is
	// present at all, distinct from an owner: section present but empty —
	// mergeFile uses this nil-ness to decide whether the current file should
	// overwrite cfg.Owner, so a later file without an owner: section never
	// silently clobbers an earlier file's already-good declaration.
	Owner *struct {
		OwnerIDs           []string `yaml:"owner_ids"`
		GatewayTokenEnv    string   `yaml:"gateway_token_env"`
		HasRecoveryCommand bool     `yaml:"has_recovery_command"`
	} `yaml:"owner"`
	Bridge struct {
		HMACEnabled          bool `yaml:"hmac_enabled"`
		ContextHeadersSigned bool `yaml:"context_headers_signed"`
	} `yaml:"bridge"`
	ChannelInstances []struct {
		Channel         string `yaml:"channel"`
		Tenant          string `yaml:"tenant"`
		DeviceSessionID string `yaml:"device_session_id"`
		ReloadStrategy  string `yaml:"reload_strategy"`
	} `yaml:"channel_instances"`
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
			User:            m.User,
			EnvMode:         m.EnvMode,
			TmpfsFlags:      m.TmpfsFlags,
			CapAdd:          m.CapAdd,
			Location:        Location{File: path, Line: lines.lookup("sandbox.mounts", i)},
		})
	}
	// sandbox.on_unavailable is a deployment-level scalar, not a list, so it
	// is threaded through separately from the per-index Sandboxes above. If
	// a deployment splits its config across multiple files and more than one
	// declares this key, the last file merged wins — the same "last write
	// wins" behavior implicit in every other singleton value in this struct.
	if line, found := lines.lookupScalar("sandbox.on_unavailable"); found {
		cfg.SandboxOnUnavailable = raw.Sandbox.OnUnavailable
		cfg.SandboxOnUnavailableDeclared = true
		cfg.SandboxOnUnavailableLocation = Location{File: path, Line: line}
	}
	// Browser is deployment-level, not a list -- only overwrite cfg.Browser
	// fields the current file actually declares, mirroring how Bridge above
	// and SandboxOnUnavailable handle "last write wins, but only for keys a
	// later file actually mentions" merging. A later file with no
	// resources.browser section at all must never silently clobber an
	// earlier file's real declaration with the zero value.
	if line, ok := lines.declaredLine("resources.browser.backend"); ok {
		cfg.Browser.BackendDeclared = true
		cfg.Browser.Backend = raw.Resources.Browser.Backend
		cfg.Browser.Location = Location{File: path, Line: line}
	}
	if line, ok := lines.declaredLine("resources.browser.backend_isolation_mode"); ok {
		cfg.Browser.IsolationModeDeclared = true
		cfg.Browser.IsolationMode = raw.Resources.Browser.BackendIsolationMode
		if !cfg.Browser.BackendDeclared {
			cfg.Browser.Location = Location{File: path, Line: line}
		}
	}
	for i, p := range raw.Resources.Browser.Profiles {
		cfg.ResourceProfiles = append(cfg.ResourceProfiles, ResourceProfile{
			Path:     p.Path,
			Location: Location{File: path, Line: lines.lookup("resources.browser.profiles", i)},
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
			Tenant:          c.Tenant,
			TargetAgent:     c.TargetAgent,
			CreatorCaptured: c.CapturesCreatorIdentity,
			Location:        Location{File: path, Line: lines.lookup("schedules.cron", i)},
		})
	}
	for i, a := range raw.Agents {
		entry := AgentEntry{
			Name:     a.Name,
			Tenant:   a.Tenant,
			Location: Location{File: path, Line: lines.lookup("agents", i)},
		}
		if a.Overrides != nil {
			entry.HasWorkspaceRestrictionOverride = a.Overrides.WorkspaceRestriction != nil
			entry.HasSandboxConfigOverride = len(a.Overrides.SandboxConfig) > 0
		}
		cfg.Agents = append(cfg.Agents, entry)
	}
	for i, p := range raw.Providers {
		cfg.Providers = append(cfg.Providers, ProviderEntry{
			Name:                        p.Name,
			OAuthTokenStorageEncryption: p.OAuth.TokenStorage.Encryption,
			Location:                    Location{File: path, Line: lines.lookup("providers", i)},
		})
	}
	if raw.Owner != nil {
		cfg.Owner = OwnerConfig{
			OwnerIDs:           raw.Owner.OwnerIDs,
			GatewayTokenEnv:    raw.Owner.GatewayTokenEnv,
			HasRecoveryCommand: raw.Owner.HasRecoveryCommand,
			Declared:           true,
			Location:           Location{File: path, Line: lines.lookupKey("owner")},
		}
	}

	// Bridge is deployment-level, not a list — only overwrite cfg.Bridge if
	// this file actually declares a bridge: section. A later file with no
	// bridge: key at all must never silently clobber an earlier file's real
	// declaration with the zero value.
	if line, ok := lines.declaredLine("bridge"); ok {
		cfg.Bridge = BridgeConfig{
			Declared:             true,
			HMACEnabled:          raw.Bridge.HMACEnabled,
			ContextHeadersSigned: raw.Bridge.ContextHeadersSigned,
			Location:             Location{File: path, Line: line},
		}
	}
	for i, c := range raw.ChannelInstances {
		cfg.ChannelInstances = append(cfg.ChannelInstances, ChannelInstance{
			Channel:         c.Channel,
			Tenant:          c.Tenant,
			DeviceSessionID: c.DeviceSessionID,
			ReloadStrategy:  c.ReloadStrategy,
			Location:        Location{File: path, Line: lines.lookup("channel_instances", i)},
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
