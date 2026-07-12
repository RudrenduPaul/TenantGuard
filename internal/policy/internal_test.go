package policy

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestToInt(t *testing.T) {
	cases := []struct {
		name   string
		in     interface{}
		want   int
		wantOK bool
	}{
		{"json.Number", json.Number("3"), 3, true},
		{"float64", float64(4), 4, true},
		{"int", 5, 5, true},
		{"invalid json.Number", json.Number("not-a-number"), 0, false},
		{"unsupported type", "a string", 0, false},
		{"nil", nil, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := toInt(c.in)
			if ok != c.wantOK || (ok && got != c.want) {
				t.Errorf("toInt(%v) = (%d, %v), want (%d, %v)", c.in, got, ok, c.want, c.wantOK)
			}
		})
	}
}

func TestErrPolicyLoadFailedMessageAndUnwrap(t *testing.T) {
	inner := errors.New("parse error")
	err := &ErrPolicyLoadFailed{RuleID: "TA01", Err: inner}
	if got := err.Error(); got == "" {
		t.Error("Error() should not be empty")
	}
	if !errors.Is(err, inner) {
		t.Error("errors.Is should unwrap to the inner error")
	}
}
