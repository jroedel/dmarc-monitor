package alertbus_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jroedel/dmarc-monitor/business/domain/alert/alertbus"
	"github.com/jroedel/dmarc-monitor/business/types/email"
	"github.com/jroedel/dmarc-monitor/business/types/severity"
)

type capturingSender struct {
	sent []alertbus.Message
}

func (s *capturingSender) Send(_ context.Context, msg alertbus.Message) error {
	s.sent = append(s.sent, msg)

	return nil
}

func newBusiness(sender alertbus.Sender) *alertbus.Business {
	return alertbus.NewBusiness(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		sender,
		alertbus.Config{
			From:          email.MustParse("dmarc@example.com"),
			To:            []email.Email{email.MustParse("webmaster@example.com")},
			SubjectPrefix: "[dmarc]",
		},
	)
}

func criticalAlert() alertbus.Alert {
	return alertbus.Alert{
		Severity:  severity.Critical,
		Preamble:  "Mail from one of your own servers is being rejected.",
		Generated: time.Date(2026, 8, 14, 6, 0, 0, 0, time.UTC),
		Items: []alertbus.Item{
			{
				Severity: severity.Critical,
				Headline: "Mail from 198.51.100.7 is being blocked",
				Domain:   "example.com",
				Subject:  "198.51.100.7",
				Detail:   "90 of 90 messages were rejected by google.com. Neither SPF nor DKIM aligned.",
				Action:   "Check whether 198.51.100.7 is one of ours.",
			},
			{
				Severity: severity.Warning,
				Headline: "New sender 192.0.2.99 for example.com",
				Domain:   "example.com",
				Subject:  "192.0.2.99",
				Detail:   "192.0.2.99 sent 120 messages and 40 failed DMARC.",
				Action:   "Confirm 192.0.2.99 should be sending as example.com.",
			},
		},
		Footer: []string{"Messages : 500 seen, 400 passed, 90 blocked"},
	}
}

// The subject line is the only part guaranteed to be read. It has to carry the
// severity, the domain and the worst headline, in that order, on one line.
func TestSubjectIsScannable(t *testing.T) {
	msg, err := newBusiness(&capturingSender{}).Render(criticalAlert())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	switch {
	case !strings.HasPrefix(msg.Subject, "[dmarc] CRITICAL: example.com — "):
		t.Errorf("subject does not lead with prefix, severity and domain: %q", msg.Subject)
	case !strings.Contains(msg.Subject, "198.51.100.7"):
		t.Errorf("subject omits the worst finding: %q", msg.Subject)
	case !strings.HasSuffix(msg.Subject, "(+1 more)"):
		t.Errorf("subject does not say more is inside: %q", msg.Subject)
	case strings.ContainsAny(msg.Subject, "\r\n"):
		t.Errorf("subject contains a newline, which is a header injection: %q", msg.Subject)
	}
}

// Header injection through a report is the realistic attack here: the headline
// is assembled from data a stranger put in an XML file.
func TestSubjectCannotBeInjected(t *testing.T) {
	alert := criticalAlert()
	alert.Items[0].Headline = "boom\r\nBcc: attacker@evil.example\r\n"

	msg, err := newBusiness(&capturingSender{}).Render(alert)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	if strings.ContainsAny(msg.Subject, "\r\n") {
		t.Fatalf("injected CRLF survived into the subject: %q", msg.Subject)
	}
}

// Every item must carry its own action, because items get forwarded on their
// own to whoever owns that server.
func TestBodyCarriesEvidenceAndAction(t *testing.T) {
	msg, err := newBusiness(&capturingSender{}).Render(criticalAlert())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	for _, want := range []string{
		"Mail from one of your own servers is being rejected.",
		"[CRITICAL]",
		"[WARNING ]",
		"198.51.100.7",
		"WHAT TO DO:",
		"Messages : 500 seen, 400 passed, 90 blocked",
	} {
		if !strings.Contains(msg.Body, want) {
			t.Errorf("body is missing %q", want)
		}
	}

	for line := range strings.SplitSeq(msg.Body, "\n") {
		if len([]rune(line)) > 80 {
			t.Errorf("line longer than 80 columns: %q", line)
		}
	}
}

// An alert with nothing in it is the failure this program is built to avoid.
func TestRefusesEmptyAlert(t *testing.T) {
	if _, err := newBusiness(&capturingSender{}).Render(alertbus.Alert{Severity: severity.Info}); err == nil {
		t.Error("rendered an alert with no items")
	}
}

func TestSendDelivers(t *testing.T) {
	sender := &capturingSender{}

	if _, err := newBusiness(sender).Send(t.Context(), criticalAlert()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if len(sender.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(sender.sent))
	}
	if got, want := sender.sent[0].To[0].String(), "webmaster@example.com"; got != want {
		t.Errorf("recipient = %q, want %q", got, want)
	}
}

// An update notice is the proof that an unattended deployment works, so it has
// to survive the same scrutiny as an alert: prefixed, single-line subject,
// delivered to the same people.
func TestNoticeIsPrefixedAndDelivered(t *testing.T) {
	sender := &capturingSender{}
	business := newBusiness(sender)

	notice := alertbus.Notice{
		Subject: "updated to v1.2.0 on mail.example.com",
		Body:    "dmarc-monitor updated itself.\n\n  from v1.1.0\n  to   v1.2.0\n",
	}

	if _, err := business.Notify(t.Context(), notice); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if len(sender.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(sender.sent))
	}

	msg := sender.sent[0]
	switch {
	case msg.Subject != "[dmarc] updated to v1.2.0 on mail.example.com":
		t.Errorf("subject = %q", msg.Subject)
	case msg.Body != notice.Body:
		t.Errorf("body was rewritten: %q", msg.Body)
	case msg.To[0].String() != "webmaster@example.com":
		t.Errorf("recipient = %q", msg.To[0])
	}
}

// A release tag is attacker-influenced in the same way a report is: it reaches
// the subject line from outside.
func TestNoticeSubjectCannotBeInjected(t *testing.T) {
	sender := &capturingSender{}

	notice := alertbus.Notice{
		Subject: "updated to v1.2.0\r\nBcc: attacker@evil.example",
		Body:    "x",
	}

	if _, err := newBusiness(sender).Notify(t.Context(), notice); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if strings.ContainsAny(sender.sent[0].Subject, "\r\n") {
		t.Fatalf("injected CRLF survived: %q", sender.sent[0].Subject)
	}
}

func TestNoticeWithoutSubjectIsRefused(t *testing.T) {
	if _, err := newBusiness(&capturingSender{}).RenderNotice(alertbus.Notice{Body: "x"}); err == nil {
		t.Error("rendered a notice with no subject")
	}
}

// The Message-ID is the only handle on a message once it has left, so it has to
// be on every message and it has to come back to the caller. A send that is
// logged without one cannot be traced into a mail server's log afterwards.
func TestSentMessagesCarryAnID(t *testing.T) {
	sender := &capturingSender{}

	msg, err := newBusiness(sender).Send(t.Context(), criticalAlert())
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	switch {
	case msg.ID.IsZero():
		t.Fatal("Send returned a message with no id")
	case sender.sent[0].ID != msg.ID:
		t.Errorf("the id sent (%s) is not the id returned (%s)", sender.sent[0].ID, msg.ID)
	case !strings.HasSuffix(msg.ID.String(), "@example.com>"):
		t.Errorf("id = %s, want it to borrow the from address's domain", msg.ID)
	}
}

// Two messages sharing an id is not a cosmetic problem: a receiver is entitled
// to treat the second as a duplicate it has already seen and drop it, which
// would silently discard the alert that mattered.
func TestEveryRenderMintsANewID(t *testing.T) {
	business := newBusiness(&capturingSender{})
	seen := make(map[string]bool)

	for range 100 {
		msg, err := business.Render(criticalAlert())
		if err != nil {
			t.Fatalf("Render: %v", err)
		}

		if seen[msg.ID.String()] {
			t.Fatalf("Message-ID %s was minted twice", msg.ID)
		}

		seen[msg.ID.String()] = true
	}
}

// A failed send must still name the message it failed to send — that is the
// case where an operator most needs the id, because nothing downstream logged
// it for them.
func TestFailedSendNamesTheMessage(t *testing.T) {
	_, err := newBusiness(&failingSender{}).Notify(t.Context(), alertbus.Notice{
		Subject: "test",
		Body:    "x",
	})
	if err == nil {
		t.Fatal("a failing sender produced no error")
	}

	if !strings.Contains(err.Error(), "@example.com>") {
		t.Errorf("error does not carry the Message-ID: %v", err)
	}
}

type failingSender struct{}

func (failingSender) Send(context.Context, alertbus.Message) error {
	return errors.New("relay said no")
}
