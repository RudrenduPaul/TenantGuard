# TA02 — MCP/Tool-Registration Validation
# Maps to goclaw#1070: a saved MCP tool URL that targets a private/loopback
# address without declared SSRF validation is an SSRF risk. Public URLs need
# no validation flag; private/loopback-looking URLs must declare it.
package tenantguard.ta02

import rego.v1

private_prefixes := [
	"http://127.",
	"https://127.",
	"http://localhost",
	"https://localhost",
	"http://169.254.",
	"https://169.254.",
	"http://10.",
	"https://10.",
	"http://192.168.",
	"https://192.168.",
]

is_private(url) if {
	some prefix in private_prefixes
	startswith(url, prefix)
}

violations contains i if {
	some i
	tool := input.mcp_tools[i]
	is_private(tool.url)
	not tool.validates_private
}
