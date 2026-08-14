// Package email is the strong type for an email address.
//
// Two of them decide where an alert goes and who it appears to come from, and a
// third is parroted back out of a report we did not write. Parsing once at the
// edge means the SMTP layer is handed something already known to be an
// addr-spec, and a malformed reporter address in an XML file can never become a
// header we send.
package email

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

// ErrInvalidEmail is returned by Parse for anything net/mail will not accept as
// a single address.
var ErrInvalidEmail = errors.New("email: not a valid address")

// Email is a validated address in addr-spec form (no display name, no angle
// brackets), lowercased in the domain part. The zero value is invalid.
type Email struct {
	value string
}

// Parse validates s as one address. A display name is accepted on input and
// discarded — reporters send "Google <noreply-dmarc@google.com>" and we want
// the address, not the branding.
func Parse(s string) (Email, error) {
	addr, err := mail.ParseAddress(strings.TrimSpace(s))
	if err != nil {
		return Email{}, fmt.Errorf("%w: %q: %w", ErrInvalidEmail, s, err)
	}

	local, domain, found := strings.Cut(addr.Address, "@")
	if !found {
		return Email{}, fmt.Errorf("%w: %q has no domain", ErrInvalidEmail, s)
	}

	return Email{value: local + "@" + strings.ToLower(domain)}, nil
}

// MustParse parses s and panics on failure; for tests and known-good constants.
func MustParse(s string) Email {
	e, err := Parse(s)
	if err != nil {
		panic(err)
	}

	return e
}

// String returns the address, or "" for the zero value.
func (e Email) String() string { return e.value }

// IsZero reports whether e is the unset zero value.
func (e Email) IsZero() bool { return e == Email{} }

// Domain returns the part after the @, or "" for the zero value. Callers that
// need it as a DNS name parse it themselves; this package deliberately does not
// import domainname, so that neither type has to know about the other.
func (e Email) Domain() string {
	_, domain, _ := strings.Cut(e.value, "@")

	return domain
}
