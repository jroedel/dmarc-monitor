// Package triagebus decides whether a set of DMARC observations is worth an
// email, and what that email should say.
//
// This is the part of the program that justifies its existence. Anyone can
// forward DMARC reports to a webmaster; the reason nobody reads them is that
// they are almost entirely routine, and the one report in fifty that matters
// looks exactly like the other forty-nine. Triage is the filter, and the whole
// design follows from one rule: **the rules here are deterministic and are the
// only thing that decides whether mail goes out.**
//
// A language model may be attached as an Explainer. It writes the paragraph at
// the top of an alert that was already going to be sent. It cannot raise a
// severity, cannot invent a finding, and cannot suppress one — so a model that
// is down, slow, or confidently wrong costs the alert its prose and nothing
// else. An LLM that could decide would be a system that alerts differently on
// Tuesday, and a webmaster who learns to distrust it.
package triagebus

import (
	"context"
	"log/slog"
	"time"
)

// Thresholds are the knobs that decide what counts as a problem. Their defaults
// live in foundation/config and are documented in the credentials template,
// because they are operator policy rather than program logic.
type Thresholds struct {
	// FailureRate is the fraction of a domain's mail that may fail DMARC before
	// it is worth mentioning. Never zero in practice: ordinary forwarding
	// breaks SPF, so every real domain fails a little all the time.
	FailureRate float64

	// MinimumVolume is how much mail a source must send before a rate is
	// computed from it at all. One failure in two messages is 50% and means
	// nothing.
	MinimumVolume int

	// NewSourceVolume is how much mail an unrecognised IP must send to be worth
	// a finding on its own.
	NewSourceVolume int
}

// Explainer is the optional port a language model implements. It is given a
// verdict that is already final and returns prose.
//
// The contract is narrow on purpose: no arguments it could use to change the
// outcome, and a return value that is only ever text. An implementation that
// fails must return an error rather than a guess — the alert is better plain
// than wrong.
type Explainer interface {
	Explain(ctx context.Context, v Verdict) (string, error)
}

// Business is the triage core.
type Business struct {
	log        *slog.Logger
	thresholds Thresholds
	explainer  Explainer
}

// NewBusiness constructs triage over a set of thresholds. explainer may be nil,
// which is the normal configuration.
func NewBusiness(log *slog.Logger, thresholds Thresholds, explainer Explainer) *Business {
	return &Business{
		log:        log,
		thresholds: thresholds,
		explainer:  explainer,
	}
}

// Assess grades a set of observations.
//
// It always returns a verdict, including the empty one — "nothing happened" is
// a result, and the caller logs it. The error return is reserved for the caller
// being unable to trust the verdict at all, which currently cannot happen.
func (b *Business) Assess(ctx context.Context, obs []Observation) (Verdict, error) {
	summary := summarize(obs)

	var findings []Finding
	for _, byDomain := range groupByDomain(obs) {
		findings = append(findings, b.assessDomain(byDomain)...)
	}

	verdict := NewVerdict(findings, summary)

	b.log.Debug("triagebus: assessed",
		"observations", len(obs),
		"findings", len(verdict.Findings),
		"severity", verdict.Severity.String())

	return b.explain(ctx, verdict), nil
}

// Explain attaches a narrative to an already-final verdict. Separate from
// Assess so the App layer can drop findings that are still in cooldown and only
// then pay for the prose — there is no point asking a model to explain an alert
// that is not going to be sent.
func (b *Business) Explain(ctx context.Context, v Verdict) Verdict {
	return b.explain(ctx, v)
}

func (b *Business) explain(ctx context.Context, v Verdict) Verdict {
	if b.explainer == nil || len(v.Findings) == 0 {
		return v
	}

	start := time.Now()

	narrative, err := b.explainer.Explain(ctx, v)
	if err != nil {
		// Deliberately not returned. The verdict is complete without it and the
		// alert must go out regardless; a model outage is not an excuse to stay
		// quiet about mail being rejected.
		b.log.Warn("triagebus: explainer failed, sending without narrative", "err", err)

		return v
	}

	b.log.Debug("triagebus: narrative written", "duration", time.Since(start), "bytes", len(narrative))
	v.Narrative = narrative

	return v
}
