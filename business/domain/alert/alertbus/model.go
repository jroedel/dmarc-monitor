package alertbus

import (
	"time"

	"github.com/jroedel/dmarc-monitor/business/types/email"
	"github.com/jroedel/dmarc-monitor/business/types/severity"
)

// Alert is one email waiting to be sent, in domain terms rather than mail
// terms. It knows nothing about MIME, headers or line endings; turning it into
// a message is the store's job, and keeping the two apart is what lets the
// dry-run path print exactly what would have gone out.
//
// It is this domain's own type rather than a triage verdict because a Business
// domain may not import another one. The narrowing is real: everything needed
// to *decide* is gone by the time an Alert exists, and what remains is what a
// person will read.
type Alert struct {
	Severity  severity.Severity
	Subject   string
	Preamble  string
	Items     []Item
	Footer    []string
	Generated time.Time
}

// Item is one thing the alert is about — a triage finding, flattened to the
// four things a webmaster needs: what, where, the evidence, and what to do.
type Item struct {
	Severity severity.Severity
	Headline string
	Domain   string
	Subject  string
	Detail   string
	Action   string
}

// Notice is a short operational message to the same people who get alerts: not
// a finding, not graded, and not about DMARC at all.
//
// It exists because a monitor that updates itself silently is a monitor you
// have to log in to verify — which is the thing the whole cron deployment was
// meant to avoid. One mail when a new build lands is the cheapest possible
// proof that the pipeline works end to end.
//
// It is a separate type from Alert on purpose. Alert refuses to render with no
// items, because an alert with nothing in it is this program's worst failure;
// a Notice has no items by nature and must not be forced through that shape.
type Notice struct {
	Subject string
	Body    string
}

// Message is the rendered email, still as data. The Sender turns it into bytes
// on the wire; a test turns it into a golden file.
type Message struct {
	// ID is minted when the message is rendered, not when it is sent, so that
	// it can be logged either way round. A send that fails still names the
	// message it failed to send, and a dry run previews the real id rather
	// than a placeholder.
	ID      email.MessageID
	From    email.Email
	To      []email.Email
	Subject string
	Body    string
}
