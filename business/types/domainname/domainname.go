// Package domainname is the strong type for a DNS domain as it appears in a
// DMARC report: the policy domain, the RFC5322.From domain, the domain a DKIM
// signature claims.
//
// A DMARC report is a document about *whose* mail failed, and the answer is
// always a domain. Comparing those domains is the single most load-bearing
// operation in the whole program — "does the header-from domain align with the
// signing domain" is what alignment means — and comparing them as bare strings
// is how a report about "Example.COM." quietly stops matching one about
// "example.com". Normalising once, at the edge, means every later comparison is
// a plain == on a value that is already lowercase and dot-free.
package domainname

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidDomainName is returned by Parse for anything that is not a
// syntactically valid DNS name.
var ErrInvalidDomainName = errors.New("domainname: not a valid DNS domain")

// DomainName is a validated, normalised DNS domain: lowercase, no trailing
// root dot. The zero value is invalid — a report whose policy domain failed to
// parse should be rejected loudly, not silently attributed to the empty domain
// and compared equal to every other broken report.
type DomainName struct {
	value string
}

// Parse normalises and validates s as a DNS domain. Case and a trailing root
// dot are insignificant in DNS, so both are removed rather than rejected:
// reports in the wild carry all three spellings of the same name.
func Parse(s string) (DomainName, error) {
	name := strings.ToLower(strings.TrimSpace(s))
	name = strings.TrimSuffix(name, ".")

	switch {
	case name == "":
		return DomainName{}, fmt.Errorf("%w: empty", ErrInvalidDomainName)
	case len(name) > 253:
		return DomainName{}, fmt.Errorf("%w: %d bytes exceeds the 253-byte limit", ErrInvalidDomainName, len(name))
	}

	for label := range strings.SplitSeq(name, ".") {
		if err := validateLabel(label); err != nil {
			return DomainName{}, fmt.Errorf("%w: %q: %w", ErrInvalidDomainName, name, err)
		}
	}

	return DomainName{value: name}, nil
}

// MustParse parses s and panics on failure; for tests and known-good constants.
func MustParse(s string) DomainName {
	d, err := Parse(s)
	if err != nil {
		panic(err)
	}

	return d
}

// String returns the normalised domain, or "" for the zero value.
func (d DomainName) String() string { return d.value }

// IsZero reports whether d is the unset zero value.
func (d DomainName) IsZero() bool { return d == DomainName{} }

// Equal reports whether d and other are the same domain. Both sides are already
// normalised, so this is an exact match — it is not the DMARC "relaxed"
// alignment test, which is Aligns.
func (d DomainName) Equal(other DomainName) bool { return d == other }

// Aligns reports whether d is DMARC-aligned with the policy domain under the
// given alignment mode (RFC 7489 §3.1). In strict mode the two must be
// identical; in relaxed mode d may be a subdomain of the policy domain, or the
// policy domain a subdomain of d — organisational-domain alignment approximated
// by the suffix test, which is what report consumers do without a public
// suffix list.
func (d DomainName) Aligns(policy DomainName, strict bool) bool {
	switch {
	case d.IsZero() || policy.IsZero():
		return false
	case d == policy:
		return true
	case strict:
		return false
	default:
		return strings.HasSuffix(d.value, "."+policy.value) || strings.HasSuffix(policy.value, "."+d.value)
	}
}

// validateLabel checks one dot-separated label against the LDH rule (RFC 1035
// §2.3.1, RFC 1123 §2.1): letters, digits and hyphens, no leading or trailing
// hyphen, 1–63 bytes. Underscores are allowed because DMARC records live under
// _dmarc labels and reports sometimes echo them back.
func validateLabel(label string) error {
	switch {
	case label == "":
		return errors.New("empty label")
	case len(label) > 63:
		return fmt.Errorf("label %q exceeds 63 bytes", label)
	case strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-"):
		return fmt.Errorf("label %q begins or ends with a hyphen", label)
	}

	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return fmt.Errorf("label %q contains %q", label, r)
		}
	}

	return nil
}
