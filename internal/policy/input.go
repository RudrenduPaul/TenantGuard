package policy

import "github.com/RudrenduPaul/TenantGuard/internal/collector"

// regoInput is the JSON shape handed to OPA as `input`. It deliberately
// excludes collector.Location — Rego only needs to identify *which* array
// index is a violation; Go maps that index back to a Location afterward.
type regoInput struct {
	Sandboxes     []regoSandbox `json:"sandboxes"`
	MCPTools      []regoMCPTool `json:"mcp_tools"`
	CronSchedules []regoCron    `json:"cron_schedules"`
	Agents        []regoAgent   `json:"agents"`
	ExecTools     []regoExec    `json:"exec_tools"`
}

type regoSandbox struct {
	Path       string   `json:"path"`
	User       string   `json:"user"`
	EnvMode    string   `json:"env_mode"`
	TmpfsFlags []string `json:"tmpfs_flags"`
	CapAdd     []string `json:"cap_add"`
}

type regoMCPTool struct {
	URL              string `json:"url"`
	ValidatesPrivate bool   `json:"validates_private"`
}

type regoCron struct {
	Tenant      string `json:"tenant"`
	TargetAgent string `json:"target_agent"`
}

type regoAgent struct {
	Name   string `json:"name"`
	Tenant string `json:"tenant"`
}

type regoApproval struct {
	Basename   string `json:"basename"`
	PathScoped bool   `json:"path_scoped"`
}

type regoExec struct {
	Name      string `json:"name"`
	EnvPolicy struct {
		DenyDirectEnvDump   bool `json:"deny_direct_env_dump"`
		DenyIndirectEnvRead bool `json:"deny_indirect_env_read"`
	} `json:"env_policy"`
	Approvals []regoApproval `json:"approvals"`
}

func toRegoInput(cfg *collector.CollectedConfig) regoInput {
	out := regoInput{}
	for _, s := range cfg.Sandboxes {
		// Normalize nil slices to empty so the JSON handed to OPA always
		// carries an array (never null) for tmpfs_flags/cap_add — this lets
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
			Path:       s.Path,
			User:       s.User,
			EnvMode:    s.EnvMode,
			TmpfsFlags: tmpfsFlags,
			CapAdd:     capAdd,
		})
	}
	for _, m := range cfg.MCPTools {
		out.MCPTools = append(out.MCPTools, regoMCPTool{URL: m.URL, ValidatesPrivate: m.ValidatesPrivate})
	}
	for _, c := range cfg.CronSchedules {
		out.CronSchedules = append(out.CronSchedules, regoCron{Tenant: c.Tenant, TargetAgent: c.TargetAgent})
	}
	for _, a := range cfg.Agents {
		out.Agents = append(out.Agents, regoAgent{Name: a.Name, Tenant: a.Tenant})
	}
	for _, e := range cfg.ExecTools {
		re := regoExec{Name: e.Name}
		re.EnvPolicy.DenyDirectEnvDump = e.EnvPolicy.DenyDirectEnvDump
		re.EnvPolicy.DenyIndirectEnvRead = e.EnvPolicy.DenyIndirectEnvRead
		for _, a := range e.Approvals {
			re.Approvals = append(re.Approvals, regoApproval{Basename: a.Basename, PathScoped: a.PathScoped})
		}
		out.ExecTools = append(out.ExecTools, re)
	}
	return out
}
