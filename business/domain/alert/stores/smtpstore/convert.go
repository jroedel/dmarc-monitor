package smtpstore

import (
	"encoding/base64"
	"fmt"
	"mime"
	"strings"
	"time"

	"github.com/jroedel/dmarc-monitor/business/domain/alert/alertbus"
)

// toSMTPMessage renders the Business message as RFC 5322 bytes.
//
// Base64 for the body rather than 8bit or quoted-printable: the alert contains
// box-drawing characters and arbitrary strings lifted out of somebody else's
// XML, and base64 is the encoding that cannot be broken by a long line, a bare
// CR, or a byte the relay decides it dislikes. The body is a few kilobytes; the
// 33% overhead costs nothing.
func toSMTPMessage(msg alertbus.Message) ([]byte, error) {
	switch {
	case msg.From.IsZero():
		return nil, fmt.Errorf("smtpstore: message has no from address")
	case len(msg.To) == 0:
		return nil, fmt.Errorf("smtpstore: message has no recipients")
	case msg.ID.IsZero():
		// Refused rather than minted here. The id is the Business layer's to
		// make, because it has to be known and logged before this point is
		// reached — including on the runs where this point is never reached at
		// all.
		return nil, fmt.Errorf("smtpstore: message has no id; it is minted when the message is rendered")
	}

	to := make([]string, 0, len(msg.To))
	for _, addr := range msg.To {
		to = append(to, addr.String())
	}

	var b strings.Builder

	// CRLF everywhere, per RFC 5321 §2.3.8. A bare LF in a header is the
	// classic way a message is accepted by the relay and mangled by the
	// receiver.
	header := func(k, v string) {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}

	header("From", msg.From.String())
	header("To", strings.Join(to, ", "))
	header("Subject", mime.QEncoding.Encode("utf-8", sanitize(msg.Subject)))
	header("Date", time.Now().Format(time.RFC1123Z))
	header("Message-ID", msg.ID.String())
	header("MIME-Version", "1.0")
	header("Content-Type", `text/plain; charset="utf-8"`)
	header("Content-Transfer-Encoding", "base64")

	// Tells well-behaved responders not to reply, so an out-of-office cannot
	// loop back into the mailbox this program reads. Auto-Submitted is the
	// header RFC 3834 defines for exactly that; X-Auto-Response-Suppress is
	// Microsoft's equivalent and is honoured by Exchange and Outlook.
	//
	// Precedence: bulk deliberately absent. It suppresses auto-replies too, but
	// it also tells filters this is bulk mail, and some act on that. This
	// message is the opposite of bulk: it is sent rarely, to one person, about
	// something that needs doing today. Buying redundant loop suppression at
	// the price of deliverability is a bad trade for the one mail that must
	// not be missed.
	header("Auto-Submitted", "auto-generated")
	header("X-Auto-Response-Suppress", "All")

	b.WriteString("\r\n")
	b.WriteString(encodeBase64(msg.Body))

	return []byte(b.String()), nil
}

// encodeBase64 wraps at 76 columns, which is the line length RFC 2045 requires.
func encodeBase64(body string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(body))

	var b strings.Builder
	for len(encoded) > 76 {
		b.WriteString(encoded[:76])
		b.WriteString("\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded)
	b.WriteString("\r\n")

	return b.String()
}

// sanitize strips CR and LF from a header value. The subject is assembled from
// finding headlines, which contain domain names and IP addresses taken out of
// reports written by strangers — a newline in one of them would end the header
// block and let the rest of the string become headers of its own.
func sanitize(s string) string {
	return strings.Join(strings.Fields(strings.NewReplacer("\r", " ", "\n", " ").Replace(s)), " ")
}
