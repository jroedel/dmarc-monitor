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

// Message is the rendered email, still as data. The Sender turns it into bytes
// on the wire; a test turns it into a golden file.
type Message struct {
	From    email.Email
	To      []email.Email
	Subject string
	Body    string
}
