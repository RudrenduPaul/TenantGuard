package policy

import "github.com/RudrenduPaul/TenantGuard/internal/collector"

// regoInput is the JSON shape handed to OPA as `input`. It deliberately
// excludes collector.Location — Rego only needs to identify *which* array
// index is a violation; Go maps that index back to a Location afterward.
type regoInput struct {
	Sandboxes []regoSandbox `json:"sandboxes"`
	// SandboxOnUnavailable and SandboxOnUnavailableDeclared back TA09, a
	// deployment-level scalar check rather than a per-index array check —
	// see collector.CollectedConfig's matching fields for why.
	SandboxOnUnavailable         string        `json:"sandbox_on_unavailable"`
	SandboxOnUnavailableDeclared bool          `json:"sandbox_on_unavailable_declared"`
	MCPTools                     []regoMCPTool `json:"mcp_tools"`
	CronSchedules                []regoCron    `json:"cron_schedules"`
	Agents                       []regoAgent   `json:"agents"`
	ExecTools                    []regoExec    `json:"exec_tools"`
}

type regoSandbox struct {
	Path string `json:"path"`
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
		out.Sandboxes = append(out.Sandboxes, regoSandbox{Path: s.Path})
	}
	out.SandboxOnUnavailable = cfg.SandboxOnUnavailable
	out.SandboxOnUnavailableDeclared = cfg.SandboxOnUnavailableDeclared
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
