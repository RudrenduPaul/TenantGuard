// Package demo bundles a single synthetic deployment config combining one
// violation of each TA01-TA05 rule plus TA09/TA10/TA13 (deployment-level
// checks), TA06 (cron creator identity), and TA07 (sandbox container
// privilege), so `tenantguard scan --demo`
// reaches a real, HIPAA-cited finding with zero setup. This closes the TTHW
// gap found during /plan-[redacted] against Trivy-class scanners, which
// can scan anything on the developer's machine with no config authoring
// required.
package demo

import (
	"embed"
	"os"
	"path/filepath"
)

//go:embed deployment.yaml
var fs embed.FS

// Materialize writes the embedded demo deployment to a fresh temp directory
// and returns its path. The caller is responsible for removing it (see
// os.MkdirTemp / os.RemoveAll pattern in cmd/tenantguard).
func Materialize() (string, error) {
	dir, err := os.MkdirTemp("", "tenantguard-demo-*")
	if err != nil {
		return "", err
	}
	data, err := fs.ReadFile("deployment.yaml")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "deployment.yaml"), data, 0o644); err != nil {
		return "", err
	}
	return dir, nil
}
