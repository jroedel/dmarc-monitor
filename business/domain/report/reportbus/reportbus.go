// Package reportbus is the Business layer for DMARC aggregate reports: getting
// them out of wherever they arrive, and handing back trustworthy models.
//
// It owns retrieval and nothing about judgement. Whether a report is worrying
// is the triage domain's question; this package's only opinions are that a
// report which cannot be parsed into valid strong types is not a report, and
// that a report is not acknowledged until the caller says it is done with it.
// The second one is what makes a crash between fetching and alerting harmless:
// the message is still unread, so the next run picks it up again.
package reportbus

import (
	"context"
	"fmt"
	"slices"
)

// Storer is the port a report source implements — an IMAP mailbox today, a
// maildir or an S3 bucket just as easily.
//
// Fetch is expected to be non-destructive: it must be safe to call twice and
// get the same reports back, because that is exactly what happens when a run
// fails between fetching and alerting. Ack is the separate, explicit step that
// makes a report stop coming back.
type Storer interface {
	// Fetch returns every unprocessed report the source holds, oldest first,
	// along with per-message problems that did not stop the fetch. A message
	// that is not a DMARC report at all is not an error — role mailboxes get
	// ordinary mail — it is simply not returned.
	Fetch(ctx context.Context) ([]Report, []error, error)

	// Ack tells the source that these refs have been fully handled and should
	// not be returned again.
	Ack(ctx context.Context, refs []string) error
}

// Business is the report core.
type Business struct {
	store Storer
}

// NewBusiness constructs the report Business over a source.
func NewBusiness(store Storer) *Business {
	return &Business{store: store}
}

// Fetch returns the unprocessed reports, sorted oldest window first so that the
// caller's view of "what changed" moves forward in time.
//
// Per-report problems are returned alongside the reports rather than instead of
// them. A single reporter sending one malformed attachment must not be able to
// stop the other twelve from being triaged — but it must also not vanish, so
// the caller can log it.
func (b *Business) Fetch(ctx context.Context) ([]Report, []error, error) {
	reports, problems, err := b.store.Fetch(ctx)
	if err != nil {
		return nil, problems, fmt.Errorf("reportbus: fetching reports: %w", err)
	}

	slices.SortStableFunc(reports, func(a, c Report) int {
		return a.Begin.Compare(c.Begin)
	})

	return reports, problems, nil
}

// Ack marks the messages behind these reports as handled. Called only after the
// caller has done everything it intends to do with them, alerting included.
func (b *Business) Ack(ctx context.Context, reports []Report) error {
	refs := make([]string, 0, len(reports))
	for _, r := range reports {
		if r.Ref != "" {
			refs = append(refs, r.Ref)
		}
	}

	if len(refs) == 0 {
		return nil
	}

	if err := b.store.Ack(ctx, slices.Compact(slices.Sorted(slices.Values(refs)))); err != nil {
		return fmt.Errorf("reportbus: acknowledging %d messages: %w", len(refs), err)
	}

	return nil
}
