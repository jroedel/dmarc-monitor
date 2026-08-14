// Package alertbus turns a graded set of findings into the one email this
// program exists to send.
//
// The whole design premise is that the webmaster reads the subject line and the
// first three lines and then decides whether to keep reading. Everything here
// serves that: the subject carries the severity, the domain and the count; the
// worst finding is first; each item states its own action; and the arithmetic
// that produced it all is at the bottom, where it can be ignored.
//
// It sends plain text. An HTML alert would render inconsistently in exactly the
// clients a webmaster uses, and there is nothing here that a table would say
// better than a paragraph.
package alertbus

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jroedel/dmarc-monitor/business/types/email"
)

// Sender is the port a delivery mechanism implements — SMTP submission today,
// a file on disk in a dry run.
type Sender interface {
	Send(ctx context.Context, msg Message) error
}

// Business is the alert core.
type Business struct {
	log           *slog.Logger
	sender        Sender
	from          email.Email
	to            []email.Email
	subjectPrefix string
}

// Config is who the alert comes from and goes to.
type Config struct {
	From          email.Email
	To            []email.Email
	SubjectPrefix string
}

// NewBusiness constructs the alert Business over a sender.
func NewBusiness(log *slog.Logger, sender Sender, cfg Config) *Business {
	return &Business{
		log:           log,
		sender:        sender,
		from:          cfg.From,
		to:            cfg.To,
		subjectPrefix: cfg.SubjectPrefix,
	}
}

// Render turns an alert into the message that would be sent. Exported so the
// dry-run path can print the real thing rather than an approximation of it —
// a preview that goes through different code is a preview of nothing.
func (b *Business) Render(alert Alert) (Message, error) {
	switch {
	case b.from.IsZero():
		return Message{}, fmt.Errorf("alertbus: no from address configured")
	case len(b.to) == 0:
		return Message{}, fmt.Errorf("alertbus: no recipients configured")
	case len(alert.Items) == 0:
		return Message{}, fmt.Errorf("alertbus: refusing to send an alert with nothing in it")
	}

	if alert.Generated.IsZero() {
		alert.Generated = time.Now()
	}

	return Message{
		From:    b.from,
		To:      b.to,
		Subject: subject(b.subjectPrefix, alert),
		Body:    body(alert),
	}, nil
}

// Send renders and delivers the alert.
func (b *Business) Send(ctx context.Context, alert Alert) error {
	msg, err := b.Render(alert)
	if err != nil {
		return err
	}

	if err := b.sender.Send(ctx, msg); err != nil {
		return fmt.Errorf("alertbus: sending alert: %w", err)
	}

	b.log.Info("alertbus: alert sent",
		"severity", alert.Severity.String(),
		"items", len(alert.Items),
		"recipients", len(b.to))

	return nil
}
