package collector_test

import (
	"errors"
	"testing"

	"github.com/RudrenduPaul/TenantGuard/internal/collector"
)

func TestErrMalformedConfigMessageAndUnwrap(t *testing.T) {
	inner := errors.New("yaml: line 4: did not find expected key")
	err := &collector.ErrMalformedConfig{File: "deployment.yaml", Line: 4, Err: inner}

	if got := err.Error(); got == "" {
		t.Error("Error() should not be empty")
	}
	if !errors.Is(err, inner) {
		t.Error("errors.Is should unwrap to the inner error")
	}
}

func TestErrNoConfigFoundMessage(t *testing.T) {
	err := &collector.ErrNoConfigFound{Target: "/some/target"}
	if got := err.Error(); got == "" {
		t.Error("Error() should not be empty")
	}
}

func TestLocationString(t *testing.T) {
	loc := collector.Location{File: "a.yaml", Line: 7}
	if got, want := loc.String(), "a.yaml:7"; got != want {
		t.Errorf("Location.String() = %q, want %q", got, want)
	}
	empty := collector.Location{}
	if got := empty.String(); got != "unknown" {
		t.Errorf("empty Location.String() = %q, want %q", got, "unknown")
	}
}
