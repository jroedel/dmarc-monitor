package email

import (
	"cmp"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrInvalidMessageID is returned by ParseMessageID for anything that is not a
// msg-id enclosed in angle brackets.
var ErrInvalidMessageID = errors.New("email: not a valid message id")

// fallbackIDDomain is used when the sending address has no domain to borrow.
// It is deliberately under .invalid (RFC 2606), so an id built from it can
// never look like it came from a real host.
const fallbackIDDomain = "dmarc-monitor.invalid"

// MessageID is an RFC 5322 msg-id, angle brackets included, exactly as it
// appears in the header.
//
// It lives here rather than in the SMTP layer because it is the only handle
// anyone has on a message once it has left this program. It is what the relay
// writes in its log and what the receiving server writes in its own, so it is
// what turns "the program says it sent something" into "here is the message,
// and here is where it went". A monitor whose alert is being silently filtered
// looks exactly like a monitor with nothing to report, and this is the thread
// that tells the two apart.
//
// Minting it in the Business layer rather than on the way out has a second
// consequence worth having: the id exists before the send is attempted, so it
// is still known — and still logged — when the send is the thing that failed.
//
// The zero value is invalid.
type MessageID struct {
	value string
}

// GenerateMessageID mints a globally unique id for a message sent from the
// given address, which supplies the domain half.
//
// The random half is crypto/rand rather than math/rand so that two hosts
// running this program cannot collide, and because a predictable Message-ID is
// a small gift to anyone trying to thread a forged reply into the webmaster's
// mailbox.
//
// Generate rather than Parse because nothing is being parsed: the value is
// created here, not validated from input somebody else wrote.
func GenerateMessageID(from Email) (MessageID, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return MessageID{}, fmt.Errorf("email: generating message id: %w", err)
	}

	domain := cmp.Or(from.Domain(), fallbackIDDomain)

	return MessageID{value: fmt.Sprintf("<%x.%d@%s>", buf, time.Now().Unix(), domain)}, nil
}

// ParseMessageID validates s as a msg-id: angle brackets around a local part,
// an @, and a domain.
//
// Deliberately looser than RFC 5322's full grammar. This exists so an id read
// back out of a log or a fixture can re-enter the type, and refusing one that a
// receiving server has already accepted would help nobody. What it does refuse
// is the case that matters: a line break, which would end the header and let
// the rest of the value become headers of its own.
func ParseMessageID(s string) (MessageID, error) {
	trimmed := strings.TrimSpace(s)

	if strings.ContainsAny(trimmed, "\r\n") {
		return MessageID{}, fmt.Errorf("%w: %q contains a line break", ErrInvalidMessageID, s)
	}

	inner, ok := strings.CutPrefix(trimmed, "<")
	if !ok {
		return MessageID{}, fmt.Errorf("%w: %q is not enclosed in angle brackets", ErrInvalidMessageID, s)
	}

	inner, ok = strings.CutSuffix(inner, ">")
	if !ok {
		return MessageID{}, fmt.Errorf("%w: %q is not enclosed in angle brackets", ErrInvalidMessageID, s)
	}

	local, domain, found := strings.Cut(inner, "@")

	switch {
	case !found:
		return MessageID{}, fmt.Errorf("%w: %q has no domain", ErrInvalidMessageID, s)
	case local == "":
		return MessageID{}, fmt.Errorf("%w: %q has nothing before the @", ErrInvalidMessageID, s)
	case domain == "":
		return MessageID{}, fmt.Errorf("%w: %q has nothing after the @", ErrInvalidMessageID, s)
	}

	return MessageID{value: trimmed}, nil
}

// MustParseMessageID parses s and panics on failure; for tests and known-good
// constants.
func MustParseMessageID(s string) MessageID {
	id, err := ParseMessageID(s)
	if err != nil {
		panic(err)
	}

	return id
}

// String returns the id with its angle brackets, or "" for the zero value.
func (m MessageID) String() string { return m.value }

// IsZero reports whether m is the unset zero value.
func (m MessageID) IsZero() bool { return m == MessageID{} }
