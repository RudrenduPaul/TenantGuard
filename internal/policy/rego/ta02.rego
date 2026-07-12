# TA02 — MCP/Tool-Registration Validation
# Maps to goclaw#1070: a saved MCP tool URL that targets a private/loopback
# address without a *verified* SSRF mitigation is an SSRF risk.
#
# "Verified" means both of the following must hold, unless the host is
# explicitly allowlisted for local/private use (allowed_private_host):
#   1. validates_private — the deployment declares an SSRF validator ran
#      against this URL at all.
#   2. pins_resolved_ip — that validator resolved the hostname ONCE and
#      pinned the resulting IP for the actual outbound connection, instead
#      of trusting the hostname again at connect time. Without pinning, an
#      attacker who controls DNS for an already-validated hostname can flip
#      the A record after validation and still reach a private/metadata
#      target — a DNS-rebinding / TOCTOU race flagged independently by
#      @m13v and @linkdao on goclaw#1070. A bare validates_private: true is
#      therefore no longer sufficient on its own.
#
# Private-target classification is real CIDR containment
# (net.cidr_contains), not string-prefix matching, applied to two sources:
#   - a literal IP embedded directly in the URL (e.g. http://127.0.0.1/...)
#   - hostname(s) resolved to IP(s) ONCE at collection time in Go — see
#     internal/collector/config.go's MCPToolEntry.ResolvedIPs. This is what
#     lets TA02 catch the exact goclaw#1070 headline repro,
#     http://host.docker.internal:8765/mcp, which resolves to a private IP
#     but has no private-looking substring in the URL text itself. Rego has
#     no usable DNS builtin here on purpose — resolution happens once at
#     collection time so a scan itself stays deterministic and offline-safe.
#
# private_cidrs mirrors goclaw's own real SSRF blocklist
# (internal/security/ssrf.go, confirmed via the goclaw#1070 thread and
# goclaw#1269 "block RFC 2544 benchmarking IPs in SSRF protection"), so this
# check is not less complete than the platform-side validator it audits:
# all three RFC1918 blocks, CGN (100.64.0.0/10), RFC 2544 benchmarking
# (198.18.0.0/15), reserved (240.0.0.0/4), and the IPv4 + IPv6
# loopback/link-local/multicast/unspecified ranges.
#
# allowed_private_host is the explicit, owner-declared escape hatch
# requested as "Option A" in the goclaw#1070 issue thread — set directly in
# TenantGuard's YAML (tools.mcp[].allowed_private_host), or auto-enriched at
# collection time from goclaw's real GOCLAW_MCP_ALLOWED_HOSTS env var (see
# internal/collector/config.go's CollectFromGoclawEnv, goclaw#1248).
package tenantguard.ta02

import rego.v1

private_cidrs := [
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"100.64.0.0/10",
	"198.18.0.0/15",
	"240.0.0.0/4",
	"::1/128",
	"fe80::/10",
	"fc00::/7",
	"ff00::/8",
	"224.0.0.0/4",
	"0.0.0.0/32",
	"::/128",
]

# url_host extracts the bare hostname (no scheme, no port, no path, no
# brackets around an IPv6 literal) from a http(s) URL string, since Rego has
# no URL-parsing builtin.
url_host(url) := host if {
	parts := regex.find_all_string_submatch_n(`^https?://(\[[0-9a-fA-F:]+\]|[^/:]+)`, url, 1)
	count(parts) > 0
	host := trim(parts[0][1], "[]")
}

is_ipv4(s) if {
	regex.match(`^([0-9]{1,3}\.){3}[0-9]{1,3}$`, s)
}

# is_ipv6 requires at least 2 colons (the minimum any real IPv6 address has,
# via "::" shorthand), so an ordinary hex-looking hostname segment with no
# colon (e.g. "cafe") is never misclassified as an IPv6 literal.
is_ipv6(s) if {
	regex.match(`^[0-9a-fA-F]*(:[0-9a-fA-F]*){2,}$`, s)
}

is_ip_literal(s) if is_ipv4(s)

is_ip_literal(s) if is_ipv6(s)

ip_in_private_cidrs(ip) if {
	is_ip_literal(ip)
	some cidr in private_cidrs
	net.cidr_contains(cidr, ip)
}

# is_private is true if the URL's own literal IP, any IP resolved for this
# tool at collection time, or the bare "localhost" hostname (kept as a
# simple literal special-case — on virtually every machine it also resolves
# to 127.0.0.1 via ResolvedIPs, but this is a cheap, network-independent
# backstop) lands in a private/loopback/reserved range.
is_private(tool) if {
	lower(url_host(tool.url)) == "localhost"
}

is_private(tool) if {
	ip_in_private_cidrs(url_host(tool.url))
}

is_private(tool) if {
	some ip in tool.resolved_ips
	ip_in_private_cidrs(ip)
}

# fully_validated requires BOTH a declared validator AND pinned-IP
# semantics — see the DNS-rebinding note in the header comment.
fully_validated(tool) if {
	tool.validates_private
	tool.pins_resolved_ip
}

violations contains i if {
	some i
	tool := input.mcp_tools[i]
	is_private(tool)
	not tool.allowed_private_host
	not fully_validated(tool)
}
