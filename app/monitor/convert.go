package monitor

import (
	"fmt"
	"strings"
	"time"

	"github.com/jroedel/dmarc-monitor/business/domain/alert/alertbus"
	"github.com/jroedel/dmarc-monitor/business/domain/report/reportbus"
	"github.com/jroedel/dmarc-monitor/business/domain/triage/triagebus"
)

// This file holds every crossing between the three Business domains. They are
// forbidden from importing each other, and this is the place that is allowed to
// know about all of them — so if a field has to travel from a report to an
// alert, it passes through here in the open.

// toTriageObservations flattens reports into the rows triage reasons about, one
// per (report, record).
//
// Two fields cannot come from the report and are supplied here: whether the
// source is already known, and whether this domain has ever been seen. Both are
// memory rather than evidence, and memory belongs to the App layer — a Business
// domain that read the state file would be a Business domain that behaves
// differently on a machine where the file was deleted.
func toTriageObservations(reports []reportbus.Report, memory sourceMemory) []triagebus.Observation {
	var obs []triagebus.Observation

	for _, r := range reports {
		firstEver := memory.KnownSourceCount(r.Domain.String()) == 0

		for _, rec := range r.Records {
			overrides := make([]string, 0, len(rec.Overrides))
			for _, o := range rec.Overrides {
				overrides = append(overrides, o.Type)
			}

			obs = append(obs, triagebus.Observation{
				ReportID:        r.ID,
				Org:             r.Org,
				Domain:          r.Domain,
				Begin:           r.Begin,
				End:             r.End,
				Policy:          r.Policy.Requested,
				SourceIP:        rec.SourceIP,
				Count:           rec.Count,
				Disposition:     rec.Disposition,
				DKIM:            rec.DKIM,
				SPF:             rec.SPF,
				HeaderFrom:      rec.HeaderFrom,
				Aligned:         rec.Aligned(r.Policy),
				Overrides:       overrides,
				KnownSource:     memory.KnownSource(r.Domain.String(), rec.SourceIP.String()),
				FirstEverReport: firstEver,
			})
		}
	}

	return obs
}

// sourceMemory is the slice of the checkpoint that triage input needs. Declared
// as an interface here, at the point of use, so the App layer's conversion can
// be tested without a state file on disk.
type sourceMemory interface {
	KnownSource(domain, ip string) bool
	KnownSourceCount(domain string) int
}

// toBusAlert converts a final verdict into the alert domain's model.
//
// Strong types are flattened to strings on the way across: an Alert is a thing
// about to become an email, and by the time it exists there is nothing left to
// decide with a severity except how to print it.
func toBusAlert(v triagebus.Verdict, generated time.Time) alertbus.Alert {
	alert := alertbus.Alert{
		Severity:  v.Severity,
		Preamble:  preamble(v),
		Footer:    footer(v.Summary, generated),
		Generated: generated,
	}

	for _, f := range v.Findings {
		alert.Items = append(alert.Items, alertbus.Item{
			Severity: f.Severity,
			Headline: f.Headline,
			Domain:   f.Domain.String(),
			Subject:  f.Subject,
			Detail:   f.Detail,
			Action:   f.Action,
		})
	}

	return alert
}

// preamble is the model's narrative when there is one, and a plain sentence of
// arithmetic when there is not. The alert must read the same either way, so the
// fallback is written to be a real opening line rather than an apology for a
// missing one.
func preamble(v triagebus.Verdict) string {
	if v.Narrative != "" {
		return v.Narrative
	}

	s := v.Summary

	var b strings.Builder

	fmt.Fprintf(&b, "%d DMARC report(s) covering %s were processed.",
		s.Reports, joinDomains(s))

	if s.Volume > 0 {
		fmt.Fprintf(&b, " They account for %d message(s), of which %d passed DMARC (%.1f%%)",
			s.Volume, s.Passing, 100*s.PassRate())

		if s.Blocked > 0 {
			fmt.Fprintf(&b, " and %d were quarantined or rejected", s.Blocked)
		}

		b.WriteString(".")
	}

	fmt.Fprintf(&b, " %d finding(s) below need attention.", len(v.Findings))

	return b.String()
}

// footer is the arithmetic, at the bottom, where someone who wants to check the
// program's working can find it and everyone else can ignore it.
func footer(s triagebus.Summary, generated time.Time) []string {
	window := "unknown"
	if !s.Window.Begin.IsZero() {
		window = fmt.Sprintf("%s to %s",
			s.Window.Begin.UTC().Format("2006-01-02 15:04 MST"),
			s.Window.End.UTC().Format("2006-01-02 15:04 MST"))
	}

	reporters := "none named"
	if len(s.Reporters) > 0 {
		reporters = strings.Join(s.Reporters, ", ")
	}

	return []string{
		fmt.Sprintf("Reporting window : %s", window),
		fmt.Sprintf("Reports processed: %d, from %s", s.Reports, reporters),
		fmt.Sprintf("Domains          : %s", joinDomains(s)),
		fmt.Sprintf("Messages         : %d seen, %d passed, %d blocked", s.Volume, s.Passing, s.Blocked),
		fmt.Sprintf("Generated        : %s by dmarc-monitor", generated.UTC().Format(time.RFC1123Z)),
	}
}

func joinDomains(s triagebus.Summary) string {
	if len(s.Domains) == 0 {
		return "no domains"
	}

	names := make([]string, 0, len(s.Domains))
	for _, d := range s.Domains {
		names = append(names, d.String())
	}

	return strings.Join(names, ", ")
}
