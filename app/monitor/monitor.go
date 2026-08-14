// Package monitor is the App layer: the one place that knows about all three
// Business domains and drives a cycle from mailbox to alert.
//
// The order of operations here is the program's correctness argument, and it is
// worth stating plainly, because every shortcut in it loses mail silently:
//
//  1. Fetch, read-only. The mailbox is untouched.
//  2. Drop reports already processed on an earlier run.
//  3. Triage, with the checkpoint's memory of known senders folded in.
//  4. Drop findings still inside their cooldown, and re-grade what is left.
//  5. Send — or, in a dry run, print.
//  6. Only now: learn the senders, record the findings as sent, and mark the
//     messages handled.
//
// Nothing is remembered until the human has been told. A crash anywhere in
// 1–5 leaves the mailbox and the state file exactly as they were, and the next
// run repeats the work. The opposite arrangement — flag first, alert second —
// turns one crash into a permanently missed alert that nothing will ever
// re-raise.
package monitor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jroedel/dmarc-monitor/business/domain/alert/alertbus"
	"github.com/jroedel/dmarc-monitor/business/domain/report/reportbus"
	"github.com/jroedel/dmarc-monitor/business/domain/triage/triagebus"
	"github.com/jroedel/dmarc-monitor/business/types/severity"
	"github.com/jroedel/dmarc-monitor/foundation/checkpoint"
)

// Monitor runs the cycle.
type Monitor struct {
	log    *slog.Logger
	report *reportbus.Business
	triage *triagebus.Business
	alert  *alertbus.Business
	state  *checkpoint.Store
	cfg    Config
}

// Config is the App layer's own policy: what to do with a verdict once it has
// one.
type Config struct {
	// Floor is the severity below which nothing is sent.
	Floor severity.Severity

	// Cooldown is how long a finding stays quiet after being sent once.
	Cooldown time.Duration

	// DryRun renders the alert and prints it instead of sending. Nothing is
	// learned, nothing is acknowledged, and the run can be repeated forever.
	DryRun bool
}

// Result is what one cycle did, for logging and for the command's exit path.
type Result struct {
	Fetched    int
	New        int
	Findings   int
	Suppressed int
	Severity   severity.Severity
	Sent       bool

	// Summary is the arithmetic triage worked from. Carried out of the cycle so
	// that a run which found nothing can still show what it looked at — "no
	// alert" and "nothing was read" must never look the same from outside.
	Summary triagebus.Summary

	Message  alertbus.Message
	Problems []error
}

// New constructs the monitor.
func New(log *slog.Logger, report *reportbus.Business, triage *triagebus.Business, alert *alertbus.Business, state *checkpoint.Store, cfg Config) *Monitor {
	return &Monitor{
		log:    log,
		report: report,
		triage: triage,
		alert:  alert,
		state:  state,
		cfg:    cfg,
	}
}

// RunOnce performs one full cycle.
func (m *Monitor) RunOnce(ctx context.Context) (Result, error) {
	now := time.Now()

	reports, problems, err := m.report.Fetch(ctx)
	if err != nil {
		return Result{Problems: problems}, err
	}

	result := Result{Fetched: len(reports), Problems: problems}

	for _, p := range problems {
		m.log.Warn("monitor: problem reading a message", "err", p)
	}

	fresh, seen := m.partitionBySeen(reports)
	result.New = len(fresh)

	m.log.Info("monitor: reports fetched",
		"total", len(reports),
		"new", len(fresh),
		"already processed", len(seen))

	// Reports that were processed on an earlier run still need acknowledging:
	// they are here because a previous run was interrupted after alerting but
	// before flagging, and leaving them unread would replay this forever.
	if len(fresh) == 0 {
		return result, m.finish(ctx, now, nil, reports)
	}

	verdict, err := m.triage.Assess(ctx, toTriageObservations(fresh, m.state))
	if err != nil {
		return result, fmt.Errorf("monitor: triage: %w", err)
	}

	verdict = m.applyCooldown(verdict, now, &result)
	result.Findings = len(verdict.Findings)
	result.Severity = verdict.Severity
	result.Summary = verdict.Summary

	if !verdict.Actionable(m.cfg.Floor) {
		m.log.Info("monitor: nothing worth sending",
			"findings", len(verdict.Findings),
			"severity", verdict.Severity.String(),
			"floor", m.cfg.Floor.String())

		return result, m.finish(ctx, now, fresh, reports)
	}

	// The narrative is written here rather than during Assess so that a model is
	// only ever asked about an alert that is actually going out.
	verdict = m.triage.Explain(ctx, verdict)

	msg, err := m.alert.Render(toBusAlert(verdict, now))
	if err != nil {
		return result, fmt.Errorf("monitor: rendering alert: %w", err)
	}
	result.Message = msg

	if m.cfg.DryRun {
		m.log.Info("monitor: dry run, not sending",
			"severity", verdict.Severity.String(),
			"findings", len(verdict.Findings))

		return result, nil
	}

	if err := m.alert.Send(ctx, toBusAlert(verdict, now)); err != nil {
		// Deliberately fatal to the cycle: nothing is learned and nothing is
		// acknowledged, so the next run tries again with the same reports.
		return result, fmt.Errorf("monitor: %w", err)
	}

	result.Sent = true

	for _, f := range verdict.Findings {
		m.state.MarkAlerted(f.Fingerprint(), now)
	}

	return result, m.finish(ctx, now, fresh, reports)
}

// Run polls until the context is cancelled. A failed cycle is logged and the
// loop continues — a mail server that is down for an hour must not take the
// monitor down with it.
func (m *Monitor) Run(ctx context.Context, interval time.Duration) error {
	m.log.Info("monitor: watching", "interval", interval)

	for {
		start := time.Now()

		result, err := m.RunOnce(ctx)
		switch {
		case errors.Is(err, context.Canceled):
			return nil
		case err != nil:
			m.log.Error("monitor: cycle failed", "err", err, "duration", time.Since(start))
		default:
			m.log.Info("monitor: cycle complete",
				"fetched", result.Fetched,
				"new", result.New,
				"findings", result.Findings,
				"sent", result.Sent,
				"duration", time.Since(start))
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

// partitionBySeen splits reports into those never processed and those a
// previous run already dealt with, keyed by the reporter's own report id.
//
// The id is the reporter's, not ours, and that is the point: the same report
// redelivered, or fetched again after an interrupted run, carries the same id
// and must not produce a second alert.
func (m *Monitor) partitionBySeen(reports []reportbus.Report) (fresh, seen []reportbus.Report) {
	for _, r := range reports {
		switch {
		case r.ID == "":
			// A report with no id cannot be deduplicated, so it is always
			// treated as new. Rare, and better than dropping it.
			fresh = append(fresh, r)
		case m.state.Seen(r.ID):
			seen = append(seen, r)
		default:
			fresh = append(fresh, r)
		}
	}

	return fresh, seen
}

// applyCooldown drops findings that were already sent recently and re-grades
// what remains.
//
// This is what stops one unfixed misconfiguration from mailing the webmaster
// every day for a month. It is applied per finding rather than per alert, so a
// new problem appearing alongside an old one still gets through immediately.
func (m *Monitor) applyCooldown(v triagebus.Verdict, now time.Time, result *Result) triagebus.Verdict {
	kept := make([]triagebus.Finding, 0, len(v.Findings))

	for _, f := range v.Findings {
		if m.state.Alerted(f.Fingerprint(), now, m.cfg.Cooldown) {
			m.log.Debug("monitor: finding suppressed by cooldown", "fingerprint", f.Fingerprint())
			result.Suppressed++

			continue
		}

		kept = append(kept, f)
	}

	return triagebus.NewVerdict(kept, v.Summary)
}

// finish records what was learned and releases the messages.
//
// Learning the senders happens here, after the alert, for the same reason
// everything else does: a source learned before the alert went out would be a
// source that is no longer new the next time around, and the alert about it
// would never be sent again.
func (m *Monitor) finish(ctx context.Context, now time.Time, processed, all []reportbus.Report) error {
	if m.cfg.DryRun {
		m.log.Info("monitor: dry run, state and mailbox left untouched")

		return nil
	}

	for _, r := range processed {
		m.state.MarkSeen(r.ID, now)

		for _, rec := range r.Records {
			m.state.LearnSource(r.Domain.String(), rec.SourceIP.String())
		}
	}

	if err := m.state.Save(now); err != nil {
		// Not fatal to the run: the alert has already gone out, and failing
		// here would only mean the mailbox is never acknowledged either.
		m.log.Error("monitor: saving state failed; the next run may repeat this work", "err", err)
	}

	if err := m.report.Ack(ctx, all); err != nil {
		return fmt.Errorf("monitor: %w", err)
	}

	return nil
}
