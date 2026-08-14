package smtpstore

import (
	"encoding/base64"
	"mime"
	"net/mail"
	"strings"
	"testing"

	"github.com/jroedel/dmarc-monitor/business/domain/alert/alertbus"
	"github.com/jroedel/dmarc-monitor/business/types/email"
)

// These tests are about the bytes on the wire. Everything upstream can be
// perfect and still arrive as nonsense, or not arrive at all, if this is wrong.

func testMessage() alertbus.Message {
	return alertbus.Message{
		From:    email.MustParse("dmarc@example.com"),
		To:      []email.Email{email.MustParse("webmaster@example.com")},
		Subject: "CRITICAL: example.com — mail from 198.51.100.7 is being blocked",
		Body:    "Line one.\nLine two — with a dash.\n",
	}
}

func parse(t *testing.T, wire []byte) *mail.Message {
	t.Helper()

	msg, err := mail.ReadMessage(strings.NewReader(string(wire)))
	if err != nil {
		t.Fatalf("the message does not parse as RFC 5322: %v", err)
	}

	return msg
}

func TestHeaders(t *testing.T) {
	wire, err := toSMTPMessage(testMessage())
	if err != nil {
		t.Fatalf("toSMTPMessage: %v", err)
	}

	msg := parse(t, wire)

	for header, want := range map[string]string{
		"From":                      "dmarc@example.com",
		"To":                        "webmaster@example.com",
		"Mime-Version":              "1.0",
		"Content-Transfer-Encoding": "base64",
		"Auto-Submitted":            "auto-generated",
		"X-Auto-Response-Suppress":  "All",
	} {
		if got := msg.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}

	// Precedence: bulk tells filters this is bulk mail, and some act on it.
	// This message is the opposite of bulk, and must not be deprioritised on
	// the one morning it matters.
	if got := msg.Header.Get("Precedence"); got != "" {
		t.Errorf("Precedence = %q, want it absent", got)
	}

	if got := msg.Header.Get("Date"); got == "" {
		t.Error("Date is missing; some receivers stamp their own and some reject")
	}

	// A Message-ID has to be globally unique and enclosed in angle brackets, or
	// threading and duplicate suppression misbehave.
	id := msg.Header.Get("Message-ID")
	if !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, ">") || !strings.Contains(id, "@example.com") {
		t.Errorf("Message-ID = %q, want <...@example.com>", id)
	}
}

// Two messages must never share a Message-ID; a receiver is entitled to treat
// the second as a duplicate and drop it.
func TestMessageIDsAreUnique(t *testing.T) {
	seen := make(map[string]bool)

	for range 100 {
		wire, err := toSMTPMessage(testMessage())
		if err != nil {
			t.Fatalf("toSMTPMessage: %v", err)
		}

		id := parse(t, wire).Header.Get("Message-ID")
		if seen[id] {
			t.Fatalf("Message-ID %q was generated twice", id)
		}

		seen[id] = true
	}
}

// The subject carries an em dash and whatever a stranger put in a report, so it
// has to survive as an encoded word rather than as raw bytes.
func TestSubjectIsEncoded(t *testing.T) {
	wire, err := toSMTPMessage(testMessage())
	if err != nil {
		t.Fatalf("toSMTPMessage: %v", err)
	}

	decoded, err := new(mime.WordDecoder).DecodeHeader(parse(t, wire).Header.Get("Subject"))
	if err != nil {
		t.Fatalf("decoding the subject: %v", err)
	}

	if want := testMessage().Subject; decoded != want {
		t.Errorf("subject arrived as %q, want %q", decoded, want)
	}
}

// The body is base64 precisely so that a long line, a bare CR or an awkward
// byte cannot corrupt it. It has to come back out identical.
func TestBodyRoundTrips(t *testing.T) {
	original := testMessage()

	wire, err := toSMTPMessage(original)
	if err != nil {
		t.Fatalf("toSMTPMessage: %v", err)
	}

	msg := parse(t, wire)

	var encoded strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := msg.Body.Read(buf)
		encoded.Write(buf[:n])
		if err != nil {
			break
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.ReplaceAll(encoded.String(), "\r\n", ""), "\n", ""))
	if err != nil {
		t.Fatalf("decoding the body: %v", err)
	}

	if string(decoded) != original.Body {
		t.Errorf("body round-tripped as %q, want %q", decoded, original.Body)
	}
}

// RFC 5321 wants CRLF. A bare LF is the classic way a message is accepted by
// the relay and mangled by the receiver.
func TestLineEndingsAreCRLF(t *testing.T) {
	wire, err := toSMTPMessage(testMessage())
	if err != nil {
		t.Fatalf("toSMTPMessage: %v", err)
	}

	text := string(wire)
	for i, r := range text {
		if r == '\n' && (i == 0 || text[i-1] != '\r') {
			t.Fatalf("bare LF at byte %d", i)
		}
	}
}

// The subject is assembled from data a stranger wrote into an XML file. A
// newline in it would end the header block and let the rest become headers.
func TestHeaderInjectionIsNeutralised(t *testing.T) {
	msg := testMessage()
	msg.Subject = "boom\r\nBcc: attacker@evil.example\r\nX-Evil: yes"

	wire, err := toSMTPMessage(msg)
	if err != nil {
		t.Fatalf("toSMTPMessage: %v", err)
	}

	parsed := parse(t, wire)

	if got := parsed.Header.Get("Bcc"); got != "" {
		t.Errorf("injected Bcc header survived: %q", got)
	}
	if got := parsed.Header.Get("X-Evil"); got != "" {
		t.Errorf("injected X-Evil header survived: %q", got)
	}
}

func TestRefusesMessagesThatCannotBeSent(t *testing.T) {
	t.Run("no recipients", func(t *testing.T) {
		msg := testMessage()
		msg.To = nil

		if _, err := toSMTPMessage(msg); err == nil {
			t.Error("built a message with no recipients")
		}
	})

	t.Run("no sender", func(t *testing.T) {
		msg := testMessage()
		msg.From = email.Email{}

		if _, err := toSMTPMessage(msg); err == nil {
			t.Error("built a message with no sender")
		}
	})
}
