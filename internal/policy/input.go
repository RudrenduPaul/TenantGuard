package policy

import "github.com/RudrenduPaul/TenantGuard/internal/collector"

// regoInput is the JSON shape handed to OPA as `input`. It deliberately
// excludes collector.Location — Rego only needs to identify *which* array
// index is a violation; Go maps that index back to a Location afterward.
type regoInput struct {
	Sandboxes []regoSandbox `json:"sandboxes"`
	// SandboxOnUnavailable and SandboxOnUnavailableDeclared back TA09, a
	// deployment-level scalar check rather than a per-index array check --
	// see collector.CollectedConfig's matching fields for why.
	SandboxOnUnavailable         string                `json:"sandbox_on_unavailable"`
	SandboxOnUnavailableDeclared bool                  `json:"sandbox_on_unavailable_declared"`
	MCPTools                     []regoMCPTool         `json:"mcp_tools"`
	CronSchedules                []regoCron            `json:"cron_schedules"`
	Agents                       []regoAgent           `json:"agents"`
	ExecTools                    []regoExec            `json:"exec_tools"`
	Providers                    []regoProvider        `json:"providers"`
	OwnerIDs                     []string              `json:"owner_ids"`
	HasRecoveryCommand           bool                  `json:"has_recovery_command"`
	HMACEnabled                  bool                  `json:"bridge_hmac_enabled"`
	ContextHeadersSigned         bool                  `json:"bridge_context_headers_signed"`
	ResourceProfiles             []regoResourceProfile `json:"resource_profiles"`
	ChannelInstances             []regoChannelInstance `json:"channel_instances"`
}

type regoSandbox struct {
	Path            string   `json:"path"`
	ScopedPerTenant bool     `json:"scoped_per_tenant"`
	User            string   `json:"user"`
	EnvMode         string   `json:"env_mode"`
	TmpfsFlags      []string `json:"tmpfs_flags"`
	CapAdd          []string `json:"cap_add"`
}

type regoResourceProfile struct {
	Path string `json:"path"`
}

// regoMCPTool is the Rego-facing shape of collector.MCPToolEntry. It carries
// everything TA02 needs to decide private-target classification (a literal
// IP in URL, or ResolvedIPs captured once at collection time) and whether
// that target is verified-safe (ValidatesPrivate + PinsResolvedIP, or an
// explicit AllowedPrivateHost escape hatch).
type regoMCPTool struct {
	URL                string   `json:"url"`
	ValidatesPrivate   bool     `json:"validates_private"`
	PinsResolvedIP     bool     `json:"pins_resolved_ip"`
	AllowedPrivateHost bool     `json:"allowed_private_host"`
	ResolvedIPs        []string `json:"resolved_ips"`
}

type regoCron struct {
	Tenant          string `json:"tenant"`
	TargetAgent     string `json:"target_agent"`
	CreatorCaptured bool   `json:"captures_creator_identity"`
}

type regoAgent struct {
	Name                            string `json:"name"`
	Tenant                          string `json:"tenant"`
	HasWorkspaceRestrictionOverride bool   `json:"has_workspace_restriction_override"`
	HasSandboxConfigOverride        bool   `json:"has_sandbox_config_override"`
}

type regoApproval struct {
	Basename   string `json:"basename"`
	PathScoped bool   `json:"path_scoped"`
}

type regoProvider struct {
	Name                        string `json:"name"`
	OAuthTokenStorageEncryption string `json:"oauth_token_storage_encryption"`
}

type regoExec struct {
	Name      string `json:"name"`
	EnvPolicy struct {
		DenyDirectEnvDump   bool `json:"deny_direct_env_dump"`
		DenyIndirectEnvRead bool `json:"deny_indirect_env_read"`
		AllowChainExec      bool `json:"allow_chain_exec"`
	} `json:"env_policy"`
	Approvals []regoApproval `json:"approvals"`
}

// regoChannelInstance is one declared messaging-channel instance. TA11
// correlates DeviceSessionID across entries to catch cross-tenant identity
// sharing (goclaw#1064/#1065). TA15 reads ReloadStrategy to catch the
// destructive full-reload blast radius (goclaw#1147).
type regoChannelInstance struct {
	Channel         string `json:"channel"`
	Tenant          string `json:"tenant"`
	DeviceSessionID string `json:"device_session_id"`
	ReloadStrategy  string `json:"reload_strategy"`
}

func toRegoInput(cfg *collector.CollectedConfig) regoInput {
	out := regoInput{}
	for _, s := range cfg.Sandboxes {
		// Normalize nil slices to empty so the JSON handed to OPA always
		// carries an array (never null) for tmpfs_flags/cap_add -- this lets
		// ta07.rego iterate them directly without needing OPA's object.get
		// null-handling.
		tmpfsFlags := s.TmpfsFlags
		if tmpfsFlags == nil {
			tmpfsFlags = []string{}
		}
		capAdd := s.CapAdd
		if capAdd == nil {
			capAdd = []string{}
		}
		out.Sandboxes = append(out.Sandboxes, regoSandbox{
			Path:            s.Path,
			ScopedPerTenant: s.ScopedPerTenant,
			User:            s.User,
			EnvMode:         s.EnvMode,
			TmpfsFlags:      tmpfsFlags,
			CapAdd:          capAdd,
		})
	}
	out.SandboxOnUnavailable = cfg.SandboxOnUnavailable
	out.SandboxOnUnavailableDeclared = cfg.SandboxOnUnavailableDeclared
	for _, r := range cfg.ResourceProfiles {
		out.ResourceProfiles = append(out.ResourceProfiles, regoResourceProfile{Path: r.Path})
	}
	for _, m := range cfg.MCPTools {
		out.MCPTools = append(out.MCPTools, regoMCPTool{
			URL:                m.URL,
			ValidatesPrivate:   m.ValidatesPrivate,
			PinsResolvedIP:     m.PinsResolvedIP,
			AllowedPrivateHost: m.ExplicitlyAllowedHost,
			ResolvedIPs:        m.ResolvedIPs,
		})
	}
	for _, c := range cfg.CronSchedules {
		out.CronSchedules = append(out.CronSchedules, regoCron{Tenant: c.Tenant, TargetAgent: c.TargetAgent, CreatorCaptured: c.CreatorCaptured})
	}
	for _, a := range cfg.Agents {
		out.Agents = append(out.Agents, regoAgent{
			Name:                            a.Name,
			Tenant:                          a.Tenant,
			HasWorkspaceRestrictionOverride: a.HasWorkspaceRestrictionOverride,
			HasSandboxConfigOverride:        a.HasSandboxConfigOverride,
		})
	}
	for _, e := range cfg.ExecTools {
		re := regoExec{Name: e.Name}
		re.EnvPolicy.DenyDirectEnvDump = e.EnvPolicy.DenyDirectEnvDump
		re.EnvPolicy.DenyIndirectEnvRead = e.EnvPolicy.DenyIndirectEnvRead
		re.EnvPolicy.AllowChainExec = e.EnvPolicy.AllowChainExec
		for _, a := range e.Approvals {
			re.Approvals = append(re.Approvals, regoApproval{Basename: a.Basename, PathScoped: a.PathScoped})
		}
		out.ExecTools = append(out.ExecTools, re)
	}
	for _, p := range cfg.Providers {
		out.Providers = append(out.Providers, regoProvider{Name: p.Name, OAuthTokenStorageEncryption: p.OAuthTokenStorageEncryption})
	}
	// OwnerIDs is always a non-nil (possibly empty) slice here so Rego's
	// count(input.owner_ids) sees a concrete array, never null — count()
	// errors on null instead of treating it as zero.
	out.OwnerIDs = cfg.Owner.OwnerIDs
	if out.OwnerIDs == nil {
		out.OwnerIDs = []string{}
	}
	out.HasRecoveryCommand = cfg.Owner.HasRecoveryCommand
	out.HMACEnabled = cfg.Bridge.HMACEnabled
	out.ContextHeadersSigned = cfg.Bridge.ContextHeadersSigned
	for _, c := range cfg.ChannelInstances {
		out.ChannelInstances = append(out.ChannelInstances, regoChannelInstance{Channel: c.Channel, Tenant: c.Tenant, DeviceSessionID: c.DeviceSessionID, ReloadStrategy: c.ReloadStrategy})
	}
	return out
}
