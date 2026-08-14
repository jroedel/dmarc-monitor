package monitor_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jroedel/dmarc-monitor/app/monitor"
	"github.com/jroedel/dmarc-monitor/business/domain/alert/alertbus"
	"github.com/jroedel/dmarc-monitor/business/domain/report/reportbus"
	"github.com/jroedel/dmarc-monitor/business/domain/triage/triagebus"
	"github.com/jroedel/dmarc-monitor/business/types/authresult"
	"github.com/jroedel/dmarc-monitor/business/types/disposition"
	"github.com/jroedel/dmarc-monitor/business/types/domainname"
	"github.com/jroedel/dmarc-monitor/business/types/email"
	"github.com/jroedel/dmarc-monitor/business/types/severity"
	"github.com/jroedel/dmarc-monitor/foundation/checkpoint"
)

// These tests are about the order of operations, which is the program's
// correctness argument: nothing is remembered, and no message is released,
// until the human has actually been told.

type fakeSource struct {
	reports []reportbus.Report
	acked   []string
	fetches int
}

func (f *fakeSource) Fetch(context.Context) ([]reportbus.Report, []error, error) {
	f.fetches++

	return slices.Clone(f.reports), nil, nil
}

func (f *fakeSource) Ack(_ context.Context, refs []string) error {
	f.acked = append(f.acked, refs...)

	return nil
}

type fakeSender struct {
	sent []alertbus.Message
	err  error
}

func (f *fakeSender) Send(_ context.Context, msg alertbus.Message) error {
	if f.err != nil {
		return f.err
	}

	f.sent = append(f.sent, msg)

	return nil
}

type harness struct {
	monitor *monitor.Monitor
	source  *fakeSource
	sender  *fakeSender
	state   *checkpoint.Store
}

func newHarness(t *testing.T, statePath string, reports []reportbus.Report, cfg monitor.Config) harness {
	t.Helper()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	source := &fakeSource{reports: reports}
	sender := &fakeSender{}

	state, err := checkpoint.Open(statePath)
	if err != nil {
		t.Fatalf("opening state: %v", err)
	}

	m := monitor.New(
		log,
		reportbus.NewBusiness(source),
		triagebus.NewBusiness(log, triagebus.Thresholds{
			FailureRate:     0.02,
			MinimumVolume:   25,
			NewSourceVolume: 50,
		}, nil),
		alertbus.NewBusiness(log, sender, alertbus.Config{
			From:          email.MustParse("dmarc@example.com"),
			To:            []email.Email{email.MustParse("webmaster@example.com")},
			SubjectPrefix: "[dmarc]",
		}),
		state,
		cfg,
	)

	return harness{monitor: m, source: source, sender: sender, state: state}
}

func defaultConfig() monitor.Config {
	return monitor.Config{Floor: severity.Warning, Cooldown: 72 * time.Hour}
}

type recordOption func(*reportbus.Record)

func record(ip string, count int, opts ...recordOption) reportbus.Record {
	rec := reportbus.Record{
		SourceIP:    netip.MustParseAddr(ip),
		Count:       count,
		Disposition: disposition.None,
		DKIM:        authresult.Pass,
		SPF:         authresult.Pass,
		HeaderFrom:  domainname.MustParse("example.com"),
	}

	for _, opt := range opts {
		opt(&rec)
	}

	return rec
}

func blocked(rec *reportbus.Record) {
	rec.Disposition = disposition.Reject
	rec.DKIM = authresult.Fail
	rec.SPF = authresult.Fail
}

func report(id, ref string, records ...reportbus.Record) reportbus.Report {
	return reportbus.Report{
		Ref:      ref,
		ID:       id,
		Org:      "google.com",
		Domain:   domainname.MustParse("example.com"),
		Begin:    time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC),
		End:      time.Date(2026, 8, 13, 23, 59, 59, 0, time.UTC),
		Received: time.Date(2026, 8, 14, 6, 0, 0, 0, time.UTC),
		Policy: reportbus.Policy{
			Domain:    domainname.MustParse("example.com"),
			Requested: disposition.Quarantine,
			Percent:   100,
		},
		Records: records,
	}
}

// A clean report sends nothing but must still release the message, or the same
// boring report is re-read forever.
func TestQuietRunAcknowledgesWithoutSending(t *testing.T) {
	h := newHarness(t, filepath.Join(t.TempDir(), "state.json"),
		[]reportbus.Report{report("r1", "101", record("203.0.113.10", 500))},
		defaultConfig())

	result, err := h.monitor.RunOnce(t.Context())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	switch {
	case len(h.sender.sent) != 0:
		t.Errorf("sent %d messages for a clean report", len(h.sender.sent))
	case !slices.Contains(h.source.acked, "101"):
		t.Errorf("message not acknowledged; acked = %v", h.source.acked)
	case result.Summary.Volume != 500:
		t.Errorf("summary volume = %d, want 500", result.Summary.Volume)
	}
}

// The full path: a sender is learned on one run, breaks on the next, and the
// webmaster gets exactly one critical email about it.
func TestKnownSenderBreakingProducesAnAlert(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")

	first := newHarness(t, statePath,
		[]reportbus.Report{report("r1", "101", record("203.0.113.10", 500))},
		defaultConfig())

	if _, err := first.monitor.RunOnce(t.Context()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if len(first.sender.sent) != 0 {
		t.Fatalf("first run sent an alert about a domain it had never seen")
	}

	second := newHarness(t, statePath,
		[]reportbus.Report{report("r2", "102",
			record("203.0.113.10", 400),
			record("203.0.113.10", 90, blocked),
		)},
		defaultConfig())

	result, err := second.monitor.RunOnce(t.Context())
	if err != nil {
		t.Fatalf("second run: %v", err)
	}

	if len(second.sender.sent) != 1 {
		t.Fatalf("sent %d alerts, want exactly 1", len(second.sender.sent))
	}

	msg := second.sender.sent[0]
	switch {
	case !strings.Contains(msg.Subject, "CRITICAL"):
		t.Errorf("subject does not carry the severity: %q", msg.Subject)
	case !strings.Contains(msg.Subject, "203.0.113.10"):
		t.Errorf("subject does not name the broken sender: %q", msg.Subject)
	case !strings.Contains(msg.Body, "WHAT TO DO:"):
		t.Error("alert body carries no action")
	case result.Severity != severity.Critical:
		t.Errorf("result severity = %s, want critical", result.Severity)
	case !result.Sent:
		t.Error("result does not record that the alert was sent")
	}
}

// The same unfixed problem tomorrow must not mail the webmaster again.
func TestCooldownSuppressesARepeat(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	reports := []reportbus.Report{report("r1", "101",
		record("203.0.113.10", 400),
		record("203.0.113.10", 90, blocked),
	)}

	// Learn the sender first, so the blocked-known-source rule can fire.
	learn := newHarness(t, statePath,
		[]reportbus.Report{report("r0", "100", record("203.0.113.10", 500))},
		defaultConfig())
	if _, err := learn.monitor.RunOnce(t.Context()); err != nil {
		t.Fatalf("learning run: %v", err)
	}

	alerting := newHarness(t, statePath, reports, defaultConfig())

	firstResult, err := alerting.monitor.RunOnce(t.Context())
	if err != nil {
		t.Fatalf("alerting run: %v", err)
	}
	if len(alerting.sender.sent) != 1 {
		t.Fatalf("first alert not sent: %d messages", len(alerting.sender.sent))
	}

	// Same finding, new report id, so nothing but the cooldown can stop it.
	repeat := newHarness(t, statePath,
		[]reportbus.Report{report("r2", "102",
			record("203.0.113.10", 400),
			record("203.0.113.10", 90, blocked),
		)},
		defaultConfig())

	result, err := repeat.monitor.RunOnce(t.Context())
	if err != nil {
		t.Fatalf("repeat run: %v", err)
	}

	// Every finding the first alert carried must be suppressed the second time,
	// and nothing may be left over to send on its own.
	switch {
	case len(repeat.sender.sent) != 0:
		t.Errorf("the same findings were mailed twice inside the cooldown")
	case result.Suppressed != firstResult.Findings:
		t.Errorf("suppressed = %d, want %d (all of the first alert's findings)", result.Suppressed, firstResult.Findings)
	case result.Findings != 0:
		t.Errorf("findings = %d, want 0; all of them were already sent", result.Findings)
	}
}

// A report already processed must not be triaged again, however it got back
// into the mailbox.
func TestSeenReportIsNotReprocessed(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	reports := []reportbus.Report{report("r1", "101", record("203.0.113.10", 500))}

	first := newHarness(t, statePath, reports, defaultConfig())
	if _, err := first.monitor.RunOnce(t.Context()); err != nil {
		t.Fatalf("first run: %v", err)
	}

	second := newHarness(t, statePath, reports, defaultConfig())

	result, err := second.monitor.RunOnce(t.Context())
	if err != nil {
		t.Fatalf("second run: %v", err)
	}

	if result.New != 0 {
		t.Errorf("new = %d, want 0; the report was processed on the first run", result.New)
	}
	if !slices.Contains(second.source.acked, "101") {
		t.Error("an already-processed report was not acknowledged, so it would come back forever")
	}
}

// If the alert cannot be delivered, nothing may be remembered or released —
// otherwise the one report that mattered is marked handled and never re-raised.
func TestFailedSendLeavesEverythingUntouched(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")

	learn := newHarness(t, statePath,
		[]reportbus.Report{report("r0", "100", record("203.0.113.10", 500))},
		defaultConfig())
	if _, err := learn.monitor.RunOnce(t.Context()); err != nil {
		t.Fatalf("learning run: %v", err)
	}

	h := newHarness(t, statePath,
		[]reportbus.Report{report("r1", "101",
			record("203.0.113.10", 400),
			record("203.0.113.10", 90, blocked),
		)},
		defaultConfig())
	h.sender.err = errors.New("relay refused the connection")

	if _, err := h.monitor.RunOnce(t.Context()); err == nil {
		t.Fatal("a failed send did not fail the cycle")
	}

	if len(h.source.acked) != 0 {
		t.Errorf("messages were acknowledged after a failed send: %v", h.source.acked)
	}

	// A fresh monitor over the same state must still see the report as new.
	retry := newHarness(t, statePath, h.source.reports, defaultConfig())

	result, err := retry.monitor.RunOnce(t.Context())
	if err != nil {
		t.Fatalf("retry run: %v", err)
	}

	switch {
	case result.New != 1:
		t.Errorf("new = %d, want 1; the failed run must not have marked it seen", result.New)
	case len(retry.sender.sent) != 1:
		t.Errorf("the retry sent %d alerts, want 1", len(retry.sender.sent))
	}
}

// A dry run must be repeatable forever: it renders the real message and changes
// nothing anywhere.
func TestDryRunChangesNothing(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")

	learn := newHarness(t, statePath,
		[]reportbus.Report{report("r0", "100", record("203.0.113.10", 500))},
		defaultConfig())
	if _, err := learn.monitor.RunOnce(t.Context()); err != nil {
		t.Fatalf("learning run: %v", err)
	}

	cfg := defaultConfig()
	cfg.DryRun = true

	h := newHarness(t, statePath,
		[]reportbus.Report{report("r1", "101",
			record("203.0.113.10", 400),
			record("203.0.113.10", 90, blocked),
		)},
		cfg)

	result, err := h.monitor.RunOnce(t.Context())
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}

	switch {
	case len(h.sender.sent) != 0:
		t.Error("a dry run sent mail")
	case len(h.source.acked) != 0:
		t.Error("a dry run acknowledged messages")
	case result.Sent:
		t.Error("a dry run reported the alert as sent")
	case result.Message.Subject == "":
		t.Error("a dry run rendered no message; there would be nothing to preview")
	case !strings.Contains(result.Message.Body, "203.0.113.10"):
		t.Error("the previewed message is not the real one")
	}
}
