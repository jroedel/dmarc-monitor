package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jroedel/dmarc-monitor/business/domain/alert/alertbus"
	"github.com/jroedel/dmarc-monitor/business/types/email"
	"github.com/jroedel/dmarc-monitor/foundation/checkpoint"
)

// The deploy notice is the one mail nobody is waiting for, so it has to justify
// itself in the subject line and the first lines of the body: which machine,
// and which build. Anyone who wants more has the commit link.
func TestDeployNotice(t *testing.T) {
	d := deployed{
		from:   "v0.1.5",
		to:     "v0.1.5-3-gabc1234",
		commit: "abc1234def5678",
	}

	notice := deployNotice(d, "/home/webmaster/dmarc-monitor/dmarc-monitor")

	host, err := os.Hostname()
	if err != nil {
		t.Fatalf("Hostname: %v", err)
	}

	switch {
	case !strings.Contains(notice.Subject, d.to):
		t.Errorf("subject does not name the new build: %q", notice.Subject)
	case !strings.Contains(notice.Subject, host):
		t.Errorf("subject does not name the machine: %q", notice.Subject)
	case strings.ContainsAny(notice.Subject, "\r\n"):
		t.Errorf("subject spans lines: %q", notice.Subject)
	}

	for _, want := range []string{
		"v0.1.5",
		"v0.1.5-3-gabc1234",
		"/home/webmaster/dmarc-monitor/dmarc-monitor",
		sourceRepo + "/commit/abc1234def5678",
		"ALERT_ON_UPDATE=false",
	} {
		if !strings.Contains(notice.Body, want) {
			t.Errorf("body is missing %q", want)
		}
	}

	t.Logf("Subject: %s\n\n%s", notice.Subject, notice.Body)
}

// The first deploy after the switch to ssh finds no version recorded, and a
// hand-built binary has no commit. Neither may leave an empty field or a link
// to nothing.
func TestDeployNoticeWithNothingRecorded(t *testing.T) {
	notice := deployNotice(deployed{to: "dev"}, "/usr/local/bin/dmarc-monitor")

	if !strings.Contains(notice.Body, "(not recorded)") {
		t.Errorf("body does not say the previous build is unknown: %q", notice.Body)
	}

	if strings.Contains(notice.Body, "/commit/") {
		t.Errorf("body links a commit it does not have: %q", notice.Body)
	}
}

// The failure notice has one job above all: to say that nothing is being
// watched. Then the error, whole, set off from the prose even when it spans
// lines, and where to look next.
func TestFailureNotice(t *testing.T) {
	cycleErr := errors.Join(
		errors.New("imapstore: logging in: NO [AUTHENTICATIONFAILED]"),
		errors.New("second line"),
	)
	since := time.Date(2026, 10, 10, 13, 0, 0, 0, time.UTC)

	notice := failureNotice(cycleErr, since)

	switch {
	case !strings.Contains(notice.Subject, "run failed on "+hostname()):
		t.Errorf("subject does not say what failed where: %q", notice.Subject)
	case strings.ContainsAny(notice.Subject, "\r\n"):
		t.Errorf("subject spans lines: %q", notice.Subject)
	}

	for _, want := range []string{
		"no DMARC report is being read",
		since.Format(time.RFC1123Z),
		"  imapstore: logging in: NO [AUTHENTICATIONFAILED]\n  second line",
		"make prod-check",
	} {
		if !strings.Contains(notice.Body, want) {
			t.Errorf("body is missing %q", want)
		}
	}

	t.Logf("Subject: %s\n\n%s", notice.Subject, notice.Body)
}

func TestRecoveryNotice(t *testing.T) {
	since := time.Date(2026, 10, 10, 13, 0, 0, 0, time.UTC)

	notice := recoveryNotice(checkpoint.Outage{Since: since, Mailed: since}, since.Add(25*time.Hour+30*time.Minute))

	if !strings.Contains(notice.Subject, "running again on") {
		t.Errorf("subject = %q", notice.Subject)
	}

	if !strings.Contains(notice.Body, "25h30m0s") {
		t.Errorf("body does not say how long it was down: %q", notice.Body)
	}
}

// relay is a sender that records what it was given, and can be told to fail.
type relay struct {
	sent []alertbus.Message
	down bool
}

func (r *relay) Send(_ context.Context, msg alertbus.Message) error {
	if r.down {
		return errors.New("relay is down")
	}

	r.sent = append(r.sent, msg)

	return nil
}

func healthFixture(t *testing.T) (*relay, *alertbus.Business, func() *checkpoint.Store, *slog.Logger) {
	t.Helper()

	r := &relay{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	alerts := alertbus.NewBusiness(log, r, alertbus.Config{
		From: email.MustParse("dmarc@example.com"),
		To:   []email.Email{email.MustParse("webmaster@example.com")},
	})

	path := filepath.Join(t.TempDir(), checkpoint.Name)
	open := func() *checkpoint.Store {
		t.Helper()

		s, err := checkpoint.Open(path)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}

		return s
	}

	return r, alerts, open, log
}

// Run by run, each reopening the state file as a real run would: the first
// failure mails, the next stays quiet, and the first success mails once and
// closes the outage.
func TestTrackHealth(t *testing.T) {
	r, alerts, open, log := healthFixture(t)
	ctx := t.Context()
	broken := errors.New("imapstore: logging in: NO")

	trackHealth(ctx, log, alerts, open(), broken, false)
	trackHealth(ctx, log, alerts, open(), broken, false)

	if len(r.sent) != 1 || !strings.Contains(r.sent[0].Subject, "run failed") {
		t.Fatalf("after two failures, sent %d: %v", len(r.sent), subjects(r.sent))
	}

	trackHealth(ctx, log, alerts, open(), nil, false)
	trackHealth(ctx, log, alerts, open(), nil, false)

	if len(r.sent) != 2 || !strings.Contains(r.sent[1].Subject, "running again") {
		t.Fatalf("after recovery, sent: %v", subjects(r.sent))
	}

	if _, failing := open().Failing(); failing {
		t.Error("still failing after a successful run")
	}
}

// When the relay is what broke, the failure mail cannot go. The outage is
// still recorded, the next run tries again, and a recovery nobody was warned
// about is not announced.
func TestTrackHealthWithTheRelayDown(t *testing.T) {
	r, alerts, open, log := healthFixture(t)
	ctx := t.Context()
	r.down = true

	trackHealth(ctx, log, alerts, open(), errors.New("smtpstore: dial: refused"), false)

	o, failing := open().Failing()
	if !failing || !o.Mailed.IsZero() {
		t.Fatalf("outage = %+v, %v; want recorded and not mailed", o, failing)
	}

	r.down = false
	trackHealth(ctx, log, alerts, open(), nil, false)

	if len(r.sent) != 0 {
		t.Errorf("announced a recovery from an outage nobody was told about: %v", subjects(r.sent))
	}
}

// A run stopped by a signal is not a failure, and -dry-run records nothing.
func TestTrackHealthRecordsNothingForCancelOrDryRun(t *testing.T) {
	r, alerts, open, log := healthFixture(t)
	ctx := t.Context()

	trackHealth(ctx, log, alerts, open(), context.Canceled, false)
	trackHealth(ctx, log, alerts, open(), errors.New("broken"), true)

	if _, failing := open().Failing(); failing {
		t.Error("a cancelled or dry run recorded an outage")
	}

	if len(r.sent) != 0 {
		t.Errorf("sent mail: %v", subjects(r.sent))
	}
}

func subjects(msgs []alertbus.Message) []string {
	out := make([]string, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, m.Subject)
	}

	return out
}
