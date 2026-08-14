package smtpstore

import (
	"crypto/rand"
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
	}

	to := make([]string, 0, len(msg.To))
	for _, addr := range msg.To {
		to = append(to, addr.String())
	}

	messageID, err := messageID(msg.From.Domain())
	if err != nil {
		return nil, err
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
	header("Message-ID", messageID)
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

// messageID builds a globally unique id. The random half is crypto/rand rather
// than math/rand so that two hosts running this program cannot collide, and
// because a predictable Message-ID is a small gift to anyone trying to thread a
// forged reply into the webmaster's mailbox.
func messageID(domain string) (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("smtpstore: generating message id: %w", err)
	}

	if domain == "" {
		domain = "dmarc-monitor.invalid"
	}

	return fmt.Sprintf("<%x.%d@%s>", buf, time.Now().Unix(), domain), nil
}

// sanitize strips CR and LF from a header value. The subject is assembled from
// finding headlines, which contain domain names and IP addresses taken out of
// reports written by strangers — a newline in one of them would end the header
// block and let the rest of the string become headers of its own.
func sanitize(s string) string {
	return strings.Join(strings.Fields(strings.NewReplacer("\r", " ", "\n", " ").Replace(s)), " ")
}
