# TA16 — LLM Provider Connection SSRF Validation
# Maps to goclaw#1430: SSRF protection blocks local MCP gateways AND local
# LLM connections (litellm, bifrost). TA02 already models the MCP-gateway
# half of that report; this rule applies the identical logic to a
# deployment's providers: list, covering the LLM-provider half.
#
# "Verified" means both of the following must hold, unless the host is
# explicitly allowlisted for local/private use (allowed_private_host):
#   1. validates_private — the deployment declares an SSRF validator ran
#      against this provider's URL at all.
#   2. pins_resolved_ip — that validator resolved the hostname ONCE and
#      pinned the resulting IP for the actual outbound connection, instead
#      of trusting the hostname again at connect time. Without pinning, an
#      attacker who controls DNS for an already-validated hostname can flip
#      the A record after validation and still reach a private/metadata
#      target — the same DNS-rebinding / TOCTOU race TA02 accounts for on
#      goclaw#1070. A bare validates_private: true is therefore not
#      sufficient on its own here either.
#
# Private-target classification, CIDR list, and the allowed_private_host
# escape hatch are identical to ta02.rego's — see that file's header for
# the full rationale (goclaw#1070, goclaw#1269, DNS-rebinding discussion).
# A provider entry with no url declared at all (URL == "") is skipped
# entirely: TA08 already covers OAuth/credential-storage hygiene for every
# provider regardless of whether it declares a connection URL, so an empty
# URL here is "not applicable to this rule," not a violation.
package tenantguard.ta16

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

# is_private is true if the provider URL's own literal IP, any IP resolved
# for this provider at collection time, or the bare "localhost" hostname
# lands in a private/loopback/reserved range. Mirrors ta02.rego's is_private
# exactly, applied to a provider entry instead of an MCP tool entry.
is_private(provider) if {
	lower(url_host(provider.url)) == "localhost"
}

is_private(provider) if {
	ip_in_private_cidrs(url_host(provider.url))
}

is_private(provider) if {
	some ip in provider.resolved_ips
	ip_in_private_cidrs(ip)
}

# fully_validated requires BOTH a declared validator AND pinned-IP
# semantics — see the DNS-rebinding note in the header comment.
fully_validated(provider) if {
	provider.validates_private
	provider.pins_resolved_ip
}

violations contains i if {
	some i
	provider := input.providers[i]
	provider.url != ""
	is_private(provider)
	not provider.allowed_private_host
	not fully_validated(provider)
}
