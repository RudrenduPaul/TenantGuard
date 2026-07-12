package collector

import "fmt"

// ErrMalformedConfig is returned when a config file cannot be parsed. The scan
// must fail loudly with the exact file and line, never silently skip the file.
type ErrMalformedConfig struct {
	File string
	Line int
	Err  error
}

func (e *ErrMalformedConfig) Error() string {
	return fmt.Sprintf("malformed config at %s:%d: %v", e.File, e.Line, e.Err)
}

func (e *ErrMalformedConfig) Unwrap() error { return e.Err }

// ErrNoConfigFound is returned when the target directory contains no recognized
// config files. A scan of an empty target must error, not silently report zero
// findings — a 0-finding PASS must always mean "scanned and clean."
type ErrNoConfigFound struct {
	Target string
}

func (e *ErrNoConfigFound) Error() string {
	return fmt.Sprintf("no config files found under %s", e.Target)
}
