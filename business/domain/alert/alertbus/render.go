package alertbus

import (
	"fmt"
	"strings"

	"github.com/jroedel/dmarc-monitor/business/types/severity"
)

// wrapAt is where prose is folded. 72 columns because the alert is read in a
// terminal as often as in a mail client, and quoted replies indent it.
const wrapAt = 72

// subject is the highest-value line in the whole program: it is what gets read
// on a phone, and on a bad day it is the only thing that gets read. Shape is
//
//	[dmarc] CRITICAL: example.com — mail from 2 senders is being blocked
//
// severity first so it sorts and filters, then the domain, then the single
// worst thing. Never a count of findings; nobody has ever acted on "3 issues".
func subject(prefix string, alert Alert) string {
	var b strings.Builder

	if prefix != "" {
		b.WriteString(prefix)
		b.WriteString(" ")
	}

	b.WriteString(strings.ToUpper(alert.Severity.String()))
	b.WriteString(": ")

	domains := distinctDomains(alert.Items)
	switch len(domains) {
	case 0:
	case 1:
		b.WriteString(domains[0])
		b.WriteString(" — ")
	default:
		fmt.Fprintf(&b, "%d domains — ", len(domains))
	}

	b.WriteString(alert.Items[0].Headline)

	if extra := len(alert.Items) - 1; extra > 0 {
		fmt.Fprintf(&b, " (+%d more)", extra)
	}

	return collapse(b.String())
}

// body lays the alert out worst-first, each item self-contained so it can be
// forwarded on its own to whoever owns that sender.
func body(alert Alert) string {
	var b strings.Builder

	if alert.Preamble != "" {
		b.WriteString(wrap(alert.Preamble, wrapAt))
		b.WriteString("\n\n")
	}

	for i, item := range alert.Items {
		fmt.Fprintf(&b, "%s\n", strings.Repeat("─", wrapAt))
		fmt.Fprintf(&b, "%s  %s\n", label(item.Severity), item.Headline)

		switch {
		case item.Subject != "":
			fmt.Fprintf(&b, "%s / %s\n", item.Domain, item.Subject)
		case item.Domain != "":
			fmt.Fprintf(&b, "%s\n", item.Domain)
		}

		b.WriteString("\n")
		b.WriteString(wrap(item.Detail, wrapAt))
		b.WriteString("\n\n")
		b.WriteString(wrap("WHAT TO DO: "+item.Action, wrapAt))
		b.WriteString("\n")

		if i == len(alert.Items)-1 {
			fmt.Fprintf(&b, "%s\n", strings.Repeat("─", wrapAt))
		}
	}

	if len(alert.Footer) > 0 {
		b.WriteString("\n")
		for _, line := range alert.Footer {
			b.WriteString(line)
			b.WriteString("\n")
		}
	}

	return b.String()
}

// label pads the severity so the items line up when scanned vertically.
func label(s severity.Severity) string {
	return fmt.Sprintf("[%-8s]", strings.ToUpper(s.String()))
}

func distinctDomains(items []Item) []string {
	var domains []string

	seen := make(map[string]bool)
	for _, item := range items {
		if item.Domain == "" || seen[item.Domain] {
			continue
		}

		seen[item.Domain] = true
		domains = append(domains, item.Domain)
	}

	return domains
}

// wrap folds text to width on word boundaries, preserving paragraph breaks.
// Written out rather than pulled in because it is fifteen lines and a
// dependency would be a dependency in the path that sends the alert.
func wrap(text string, width int) string {
	var out []string

	for paragraph := range strings.SplitSeq(text, "\n\n") {
		var (
			line  strings.Builder
			lines []string
		)

		for _, word := range strings.Fields(paragraph) {
			switch {
			case line.Len() == 0:
				line.WriteString(word)
			case line.Len()+1+len(word) <= width:
				line.WriteString(" ")
				line.WriteString(word)
			default:
				lines = append(lines, line.String())
				line.Reset()
				line.WriteString(word)
			}
		}

		if line.Len() > 0 {
			lines = append(lines, line.String())
		}

		out = append(out, strings.Join(lines, "\n"))
	}

	return strings.Join(out, "\n\n")
}

// collapse flattens a subject to one line. A newline in a header is a header
// injection, not a formatting mistake, and the strings folded into a subject
// here came out of a report somebody else wrote.
func collapse(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")

	return strings.Join(strings.Fields(s), " ")
}
