// Package severity is the strong type for how loudly a triage finding should
// be heard.
//
// The program exists to send *few* emails, so severity is the throttle: it is
// the value compared against the configured alert floor, and the reason a
// report full of routine forwarder noise produces nothing at all. It is ordered
// rather than a bare enum because "at least warning" is the question actually
// being asked, and ordering it here keeps that comparison out of every caller.
package severity

import (
	"errors"
	"fmt"
)

// ErrInvalidSeverity is returned by Parse for an unrecognised level.
var ErrInvalidSeverity = errors.New("severity: must be one of info, notice, warning, critical")

// Severity is an ordered alert level. The zero value is invalid; a finding that
// forgot to grade itself must not sort below "info" and disappear.
type Severity struct {
	value string
	rank  int
}

var (
	// Info is worth recording, never worth an email on its own.
	Info = Severity{value: "info", rank: 1}

	// Notice is a change worth knowing about that is not yet costing mail —
	// a new sending source that authenticates cleanly, say.
	Notice = Severity{value: "notice", rank: 2}

	// Warning is mail failing authentication while policy still lets it through:
	// the window in which a misconfiguration can be fixed for free.
	Warning = Severity{value: "warning", rank: 3}

	// Critical is legitimate-looking mail being quarantined or rejected, or a
	// large unauthenticated volume claiming the domain. Someone should look today.
	Critical = Severity{value: "critical", rank: 4}
)

// Parse validates s as a severity level.
func Parse(s string) (Severity, error) {
	switch s {
	case Info.value:
		return Info, nil
	case Notice.value:
		return Notice, nil
	case Warning.value:
		return Warning, nil
	case Critical.value:
		return Critical, nil
	default:
		return Severity{}, fmt.Errorf("%w: got %q", ErrInvalidSeverity, s)
	}
}

// MustParse parses s and panics on failure; for tests and known-good constants.
func MustParse(s string) Severity {
	sev, err := Parse(s)
	if err != nil {
		panic(err)
	}

	return sev
}

// String returns the level, or "" for the zero value.
func (s Severity) String() string { return s.value }

// IsZero reports whether s is the unset zero value.
func (s Severity) IsZero() bool { return s == Severity{} }

// AtLeast reports whether s is as severe as floor. The zero value is never at
// least anything, including itself.
func (s Severity) AtLeast(floor Severity) bool {
	return !s.IsZero() && !floor.IsZero() && s.rank >= floor.rank
}

// Compare orders two severities, for slices.SortFunc and slices.Max.
func Compare(a, b Severity) int { return a.rank - b.rank }
