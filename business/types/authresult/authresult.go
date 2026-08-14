// Package authresult is the strong type for the DMARC-evaluated outcome of one
// authentication mechanism — the <dkim> and <spf> elements inside
// <policy_evaluated> (RFC 7489 Appendix C).
//
// This is deliberately *not* the raw SPF/DKIM result. The raw results live in
// <auth_results> and have a much wider vocabulary (temperror, permerror,
// softfail, neutral…); the policy-evaluated result is the reporter's verdict
// after alignment was applied, and it is binary. Keeping them as different
// types stops a "softfail" from ever being compared against the pass/fail that
// drives an alert.
package authresult

import "errors"

// ErrInvalidAuthResult is returned by Parse for an unrecognised result.
var ErrInvalidAuthResult = errors.New("authresult: must be one of pass, fail")

// AuthResult is a DMARC-evaluated pass/fail. The zero value is invalid so that
// a report missing the element fails to parse rather than defaulting to
// whichever of the two is less alarming.
type AuthResult struct {
	value string
}

var (
	// Pass means the mechanism authenticated *and* aligned with the policy domain.
	Pass = AuthResult{value: "pass"}

	// Fail means it did not — either the mechanism failed, or it passed for a
	// domain that does not align. The report does not distinguish the two here;
	// <auth_results> is where that detail lives.
	Fail = AuthResult{value: "fail"}
)

// Parse validates s as a DMARC-evaluated result.
func Parse(s string) (AuthResult, error) {
	switch s {
	case Pass.value:
		return Pass, nil
	case Fail.value:
		return Fail, nil
	default:
		return AuthResult{}, ErrInvalidAuthResult
	}
}

// MustParse parses s and panics on failure; for tests and known-good constants.
func MustParse(s string) AuthResult {
	r, err := Parse(s)
	if err != nil {
		panic(err)
	}

	return r
}

// String returns the result, or "" for the zero value.
func (r AuthResult) String() string { return r.value }

// IsZero reports whether r is the unset zero value.
func (r AuthResult) IsZero() bool { return r == AuthResult{} }

// Passed reports whether the mechanism authenticated and aligned.
func (r AuthResult) Passed() bool { return r == Pass }
