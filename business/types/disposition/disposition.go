// Package disposition is the strong type for what the receiver actually did
// with a message — the <disposition> element of <policy_evaluated>.
//
// This is the difference between "we are being told about failures" and "mail
// is being thrown away", and it is the axis an alert is graded on. A domain
// sitting at p=none can fail every check in the report and lose nothing; the
// same failures under p=reject are lost mail. The two must never be confused,
// so the disposition is a named type rather than a string that reads fine in
// either sentence.
package disposition

import "errors"

// ErrInvalidDisposition is returned by Parse for an unrecognised disposition.
var ErrInvalidDisposition = errors.New("disposition: must be one of none, quarantine, reject")

// Disposition is the applied policy action. The zero value is invalid.
type Disposition struct {
	value string
}

var (
	// None means delivered as if DMARC had not been applied — monitoring only.
	None = Disposition{value: "none"}

	// Quarantine means delivered somewhere the recipient may never look.
	Quarantine = Disposition{value: "quarantine"}

	// Reject means the message did not arrive at all.
	Reject = Disposition{value: "reject"}
)

// Parse validates s as a disposition.
func Parse(s string) (Disposition, error) {
	switch s {
	case None.value:
		return None, nil
	case Quarantine.value:
		return Quarantine, nil
	case Reject.value:
		return Reject, nil
	default:
		return Disposition{}, ErrInvalidDisposition
	}
}

// MustParse parses s and panics on failure; for tests and known-good constants.
func MustParse(s string) Disposition {
	d, err := Parse(s)
	if err != nil {
		panic(err)
	}

	return d
}

// String returns the disposition, or "" for the zero value.
func (d Disposition) String() string { return d.value }

// IsZero reports whether d is the unset zero value.
func (d Disposition) IsZero() bool { return d == Disposition{} }

// Delivered reports whether the message reached the inbox unmolested. Only
// None does; quarantine is a delivery the recipient probably never saw.
func (d Disposition) Delivered() bool { return d == None }
