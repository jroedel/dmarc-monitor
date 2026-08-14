package kronkllm

import (
	"fmt"
	"strings"

	"github.com/jroedel/dmarc-monitor/business/domain/triage/triagebus"
)

// systemPrompt is written against the one failure mode that matters here: a
// local model, given a list of authentication failures, will happily invent a
// cause for them. The findings it is shown are already true; anything it adds
// is not.
//
// It is also told to be short. The value of this paragraph is that a webmaster
// can read one sentence and know whether to open the rest — a summary as long
// as the findings has no reason to exist.
const systemPrompt = `You are writing the opening of an operational alert email to a webmaster about DMARC aggregate reports.

Rules:
- Write 2-4 sentences of plain prose. No headings, no bullet points, no markdown, no sign-off.
- Say what changed and why it matters to this domain's mail. Lead with the worst thing.
- Use ONLY the facts given below. Do not invent causes, IP owners, service names, dates or numbers.
- If a cause is uncertain, say what would distinguish the possibilities. Never assert one.
- Do not tell the reader to "monitor" or "review" anything; the findings already state the action.
- Do not repeat the findings verbatim; frame them.
- Plain English. No jargon beyond SPF, DKIM, DMARC.`

// toPrompt renders the verdict as the facts the model is allowed to use.
//
// Deliberately a flat, labelled list rather than JSON: small local models
// follow prose structure more reliably than they follow a schema, and this is
// read by a human debugging a bad narrative at least as often as by a model.
func toPrompt(v triagebus.Verdict) string {
	var b strings.Builder

	s := v.Summary

	fmt.Fprintf(&b, "Reporting window: %s to %s\n", s.Window.Begin.Format("2006-01-02 15:04 MST"), s.Window.End.Format("2006-01-02 15:04 MST"))
	fmt.Fprintf(&b, "Reports processed: %d, from: %s\n", s.Reports, strings.Join(s.Reporters, ", "))

	domains := make([]string, 0, len(s.Domains))
	for _, d := range s.Domains {
		domains = append(domains, d.String())
	}
	fmt.Fprintf(&b, "Domains covered: %s\n", strings.Join(domains, ", "))
	fmt.Fprintf(&b, "Messages seen: %d, of which %d passed DMARC and %d were quarantined or rejected.\n", s.Volume, s.Passing, s.Blocked)
	fmt.Fprintf(&b, "Overall severity: %s\n\n", v.Severity)

	b.WriteString("Findings, worst first:\n")
	for i, f := range v.Findings {
		fmt.Fprintf(&b, "\n%d. [%s] %s\n", i+1, f.Severity, f.Headline)
		fmt.Fprintf(&b, "   Domain: %s\n", f.Domain)
		if f.Subject != "" {
			fmt.Fprintf(&b, "   Source: %s\n", f.Subject)
		}
		fmt.Fprintf(&b, "   Messages affected: %d\n", f.Volume)
		fmt.Fprintf(&b, "   Evidence: %s\n", f.Detail)
		fmt.Fprintf(&b, "   Recommended action: %s\n", f.Action)
	}

	b.WriteString("\nWrite the opening paragraph now.")

	return b.String()
}
