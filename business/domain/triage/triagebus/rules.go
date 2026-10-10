package triagebus

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/jroedel/dmarc-monitor/business/types/disposition"
	"github.com/jroedel/dmarc-monitor/business/types/domainname"
	"github.com/jroedel/dmarc-monitor/business/types/severity"
)

// The rules below are ordered by how much they cost a human to act on, and each
// one exists because the alternative is a webmaster reading XML. They share one
// principle: a finding must name a source, a volume, and a thing to do. A
// finding that says "authentication failures increased" is noise with a
// severity attached.

// assessDomain runs every rule over one domain's observations.
func (b *Business) assessDomain(obs []Observation) []Finding {
	if len(obs) == 0 {
		return nil
	}

	domain := obs[0].Domain
	sources := groupBySource(obs)
	totals := totalOf(obs)

	// The per-source rules first, because the domain-wide rule is about what
	// they leave unexplained.
	findings := slices.Concat(
		b.blockedKnownSources(domain, sources),
		b.failingKnownSources(domain, sources),
		b.newSources(domain, sources),
	)

	if f, ok := b.domainWideFailure(domain, totals, sources, findings); ok {
		findings = append(findings, f)
	}

	if f, ok := b.readyToEnforce(domain, totals, obs); ok {
		findings = append(findings, f)
	}

	return findings
}

// blockedKnownSources is the critical case and the reason the program exists:
// a server this domain has legitimately used before is now having its mail
// quarantined or rejected. That is real mail not arriving, right now, and it is
// almost always a key rotation, an IP change or an expired SPF include.
//
// It is graded on how much of the server's mail fails, not on how much was
// blocked. Under pct= below 100 the receiver blocks only a sample of the
// failures, so the blocked count understates the problem by the same factor;
// what fails is what a pct=100 would block. A server failing below the
// failure-rate threshold still gets the finding, as a warning, worded as the
// handful of messages it is.
func (b *Business) blockedKnownSources(domain domainname.DomainName, sources []sourceStats) []Finding {
	var findings []Finding

	for _, s := range sources {
		switch {
		case s.blocked == 0, !s.known, s.excused == s.volume:
			continue
		}

		level := severity.Warning
		headline := fmt.Sprintf("%s from %s %s %s", count(s.blocked, "message", "messages"), s.ip, were(s.blocked), s.blockedVerb())

		if share(s.failing(), s.volume) >= b.thresholds.FailureRate {
			level = severity.Critical
			headline = fmt.Sprintf("Mail from %s is being blocked", s.ip)
		}

		findings = append(findings, Finding{
			Severity: level,
			Code:     "blocked-known-source",
			Domain:   domain,
			Subject:  s.ip.String(),
			Volume:   s.blocked,
			Headline: headline,
			Detail:   s.blockedDetail(domain),
			Action: fmt.Sprintf(
				"Check what %s is: if it is one of ours, its SPF entry or DKIM key has probably changed or expired. "+
					"If it is not ours, someone is sending as %s and DMARC is correctly stopping them.",
				s.ip, domain),
		})
	}

	return findings
}

// blockedDetail is the evidence for a blocked source: how much failed, how
// much of that the receiver blocked, how much got through only by sampling,
// and what the receiver saw on the messages that failed.
func (s sourceStats) blockedDetail(domain domainname.DomainName) string {
	failing := s.failing()

	// Default: the usual shape, where the blocked messages are among the
	// failures. A receiver can also block mail that passed, on its own policy,
	// and then the failures are not the story.
	opening := fmt.Sprintf(
		"%s has sent mail for %s before, but %d of its %s in this reporting window failed DMARC, and %s %s %d of them.",
		s.ip, domain, failing, count(s.volume, "message", "messages"), listOrgs(s.blockers), s.blockedVerb(), s.blocked)
	if failing < s.blocked {
		opening = fmt.Sprintf(
			"%s has sent mail for %s before, but %d of its %s in this reporting window %s %s by %s.",
			s.ip, domain, s.blocked, count(s.volume, "message", "messages"), were(s.blocked), s.blockedVerb(), listOrgs(s.blockers))
	}

	var sampled string
	switch {
	case s.sampled == 1:
		sampled = "One more was delivered only because the policy's pct= sampling skipped it; at pct=100 it would have been blocked too."
	case s.sampled > 1:
		sampled = fmt.Sprintf("Another %d were delivered only because the policy's pct= sampling skipped them; at pct=100 they would have been blocked too.", s.sampled)
	}

	return sentences(opening, sampled, s.evidence.describe())
}

// failingKnownSources catches the same problem one stage earlier: a known
// sender failing authentication while the published policy still lets the mail
// through. This is the window in which the fix costs nothing, which is exactly
// why it is worth an email.
func (b *Business) failingKnownSources(domain domainname.DomainName, sources []sourceStats) []Finding {
	var findings []Finding

	for _, s := range sources {
		failing := s.failing()

		switch {
		case !s.known, s.blocked > 0, failing == 0:
			continue
		case s.volume < b.thresholds.MinimumVolume:
			continue
		case share(failing, s.volume) < b.thresholds.FailureRate:
			continue
		case s.excused == failing:
			// Every failure was one the receiver told us to expect.
			continue
		}

		// Default: p=none, where failing mail is delivered by design. Under an
		// enforcing policy nothing was blocked only because pct= sampled every
		// failure out, and the next sample will not be so kind.
		delivered := fmt.Sprintf("The published policy is p=%s, so the mail was still delivered — for now.", s.policy)
		action := fmt.Sprintf(
			"Fix this before %s moves to quarantine or reject: add %s to the SPF record, or sign its mail with a DKIM key published for %s.",
			domain, s.ip, domain)

		if s.policy != disposition.None {
			delivered = fmt.Sprintf("The published policy is p=%s, and the mail was delivered only because the policy's pct= sampling skipped it this time.", s.policy)
			action = fmt.Sprintf(
				"Fix this before a receiver blocks it: add %s to the SPF record, or sign its mail with a DKIM key published for %s.",
				s.ip, domain)
		}

		findings = append(findings, Finding{
			Severity: severity.Warning,
			Code:     "failing-known-source",
			Domain:   domain,
			Subject:  s.ip.String(),
			Volume:   failing,
			Headline: fmt.Sprintf("%s is failing authentication for %s", s.ip, domain),
			Detail: sentences(
				fmt.Sprintf("%d of %s (%s) from %s failed DMARC, reported by %s.",
					failing, count(s.volume, "message", "messages"), percent(failing, s.volume), s.ip, s.orgList()),
				s.evidence.describe(),
				delivered),
			Action: action,
		})
	}

	return findings
}

// newSources reports a sender the domain has never used before. It is the
// signal that catches a marketing tool somebody signed up for on Friday, and
// the one that catches a spoofing campaign — the report cannot tell those
// apart, and neither can this program, which is why the finding names the
// volume and asks rather than concludes.
func (b *Business) newSources(domain domainname.DomainName, sources []sourceStats) []Finding {
	var findings []Finding

	for _, s := range sources {
		switch {
		case s.known, s.firstEver:
			// On the very first run every source is new; saying so would produce
			// one alert per sender and teach the webmaster to ignore all of them.
			continue
		case s.volume < b.thresholds.NewSourceVolume:
			continue
		case s.blocked > 0:
			// Already covered, more urgently, by the blocked rules.
			continue
		}

		level := severity.Notice
		detail := fmt.Sprintf(
			"%s sent %s as %s and %s authenticated correctly. It has not appeared in any earlier report.",
			s.ip, count(s.volume, "message", "messages"), domain, allOf(s.volume))

		if s.passing < s.volume {
			level = severity.Warning
			detail = sentences(
				fmt.Sprintf("%s sent %s as %s, of which %d failed DMARC. It has not appeared in any earlier report.",
					s.ip, count(s.volume, "message", "messages"), domain, s.failing()),
				s.evidence.describe())
		}

		findings = append(findings, Finding{
			Severity: level,
			Code:     "new-source",
			Domain:   domain,
			Subject:  s.ip.String(),
			Volume:   s.volume,
			Headline: fmt.Sprintf("New sender %s for %s", s.ip, domain),
			Detail:   detail,
			Action: fmt.Sprintf(
				"Confirm %s is a service that should be sending as %s. If it is, add it to SPF or DKIM. If it is not, it is being spoofed.",
				s.ip, domain),
		})
	}

	return findings
}

// domainWideFailure catches the case the per-source rules miss: no single
// sender is bad enough to trip a threshold, but the domain as a whole is
// failing more than it should. That shape is usually a policy or record
// problem — a broken SPF include, a DKIM record removed — rather than one
// misbehaving server.
//
// It counts only the failures the findings before it leave unexplained. A
// sender already named has its own finding; counting it again here produced an
// alert that named a culprit and then said no single sender was responsible.
// The rate is still taken over all of the domain's mail, because the question
// is how much of the domain is affected.
func (b *Business) domainWideFailure(domain domainname.DomainName, t totals, sources []sourceStats, named []Finding) (Finding, bool) {
	explained := make(map[string]bool, len(named))
	for _, f := range named {
		explained[f.Subject] = true
	}

	var (
		failing, blocked, excused, senders int
		sender                             netip.Addr
		seen                               = make(evidence)
	)

	for _, s := range sources {
		if explained[s.ip.String()] || s.failing() == 0 {
			continue
		}

		failing += s.failing()
		blocked += s.blocked
		excused += s.excused
		senders++
		sender = s.ip
		seen.merge(s.evidence)
	}

	switch {
	case t.volume < b.thresholds.MinimumVolume, failing == 0:
		return Finding{}, false
	case share(failing, t.volume) < b.thresholds.FailureRate:
		return Finding{}, false
	case excused == failing:
		return Finding{}, false
	}

	level := severity.Warning
	if blocked > 0 {
		level = severity.Critical
	}

	headline := fmt.Sprintf("%s of mail claiming %s is failing DMARC", percent(failing, t.volume), domain)
	detail := fmt.Sprintf(
		"%d of %s failed DMARC and %d %s blocked, spread across %s, none failing enough to be named on its own. "+
			"That shape usually means the domain's own SPF or DKIM record is wrong rather than one server being misconfigured.",
		failing, count(t.volume, "message", "messages"), blocked, were(blocked), count(senders, "sender", "senders"))

	// One sender is not a domain-wide pattern, whatever kept it from being
	// named: too little mail to judge on its own, or the first report ever.
	action := fmt.Sprintf(
		"Check the current SPF and DKIM records for %s — an include that stopped resolving, or a selector that no longer exists, produces exactly this pattern.",
		domain)

	if senders == 1 {
		detail = fmt.Sprintf(
			"%d of %s failed DMARC and %d %s blocked, all of them from %s, which sent too little to be judged on its own or has no history yet.",
			failing, count(t.volume, "message", "messages"), blocked, were(blocked), sender)
		action = fmt.Sprintf(
			"Check what %s is: if it is one of ours, add it to the SPF record or sign its mail with a DKIM key published for %s. If it is not ours, someone is sending as %s.",
			sender, domain, domain)
	}

	if len(explained) > 0 {
		headline = "Another " + headline
		detail = fmt.Sprintf(
			"Apart from the senders above, %d of the domain's %s failed DMARC and %d %s blocked, from %s.",
			failing, count(t.volume, "message", "messages"), blocked, were(blocked), count(senders, "other sender", "other senders"))
	}

	return Finding{
		Severity: level,
		Code:     "domain-failure-rate",
		Domain:   domain,
		Volume:   failing,
		Headline: headline,
		Detail:   sentences(detail, seen.describe()),
		Action:   action,
	}, true
}

// readyToEnforce is the one finding that is good news, and it is here because
// a monitoring-only DMARC policy protects nothing. A domain whose mail passes
// cleanly at volume, sitting at p=none, is a domain that could be enforcing —
// and nobody ever notices that on their own.
func (b *Business) readyToEnforce(domain domainname.DomainName, t totals, obs []Observation) (Finding, bool) {
	// Ten times the volume needed to trust a rate, because this asks the
	// webmaster to make a change that can lose mail if the evidence is thin.
	minimum := b.thresholds.MinimumVolume * 10

	switch {
	case t.policy != disposition.None, t.volume < minimum:
		return Finding{}, false
	case t.passing != t.volume:
		return Finding{}, false
	case len(sourcesOf(obs)) < 2:
		// One sender passing is not evidence that every sender is known.
		return Finding{}, false
	}

	return Finding{
		Severity: severity.Notice,
		Code:     "ready-to-enforce",
		Domain:   domain,
		Volume:   t.volume,
		Headline: fmt.Sprintf("%s could move from p=none to enforcement", domain),
		Detail: fmt.Sprintf(
			"All %d messages from %d distinct sources passed DMARC in this window, and the published policy is still p=none. "+
				"Nothing is currently being protected: anyone can send as %s and receivers will deliver it.",
			t.volume, len(sourcesOf(obs)), domain),
		Action: fmt.Sprintf(
			"Consider p=quarantine with pct=25 for %s, watch a week of reports, then raise it. Do not jump straight to p=reject.",
			domain),
	}, true
}

// sourceStats is one sending IP's behaviour for one domain, across every report
// in the batch.
type sourceStats struct {
	ip        netip.Addr
	volume    int
	passing   int
	blocked   int
	excused   int
	known     bool
	firstEver bool
	policy    disposition.Disposition
	orgs      []string
	rejected  int

	// blockers are the receivers that quarantined or rejected any of it, which
	// is not every receiver that reported it.
	blockers []string

	// sampled is failing mail the receiver delivered only because pct= told
	// it to skip the policy for that message.
	sampled int

	// evidence is what the receiver saw on the messages that failed.
	evidence evidence
}

func (s sourceStats) failing() int { return s.volume - s.passing }

// blockedVerb describes what actually happened, since "blocked" is not what an
// operator will see in their own logs.
func (s sourceStats) blockedVerb() string {
	switch s.rejected {
	case s.blocked:
		return "rejected"
	case 0:
		return "quarantined"
	default:
		return "quarantined or rejected"
	}
}

func (s sourceStats) orgList() string { return listOrgs(s.orgs) }

func listOrgs(orgs []string) string {
	switch len(orgs) {
	case 0:
		return "the reporting receivers"
	case 1:
		return orgs[0]
	default:
		return fmt.Sprintf("%s and %s", orgs[0], count(len(orgs)-1, "other receiver", "other receivers"))
	}
}

// evidence counts failing messages by what the receiver saw when it checked
// them, which is the first thing anyone investigating needs and the last thing
// a raw report makes obvious. Keyed by the description itself, so that rows
// from different reports with the same story add up.
type evidence map[string]int

func (e evidence) add(o Observation) { e[checkedAs(o)] += o.Count }

func (e evidence) merge(other evidence) {
	for text, n := range other {
		e[text] += n
	}
}

// describe says what the failing messages had in common, most common first.
// It names at most three patterns: past that, the report is the place to look.
func (e evidence) describe() string {
	const shown = 3

	if len(e) == 0 {
		return ""
	}

	total := 0
	for _, n := range e {
		total += n
	}

	patterns := slices.SortedFunc(maps.Keys(e), func(a, b string) int {
		if c := cmp.Compare(e[b], e[a]); c != 0 {
			return c
		}

		return strings.Compare(a, b)
	})

	switch {
	case len(patterns) == 1 && total == 1:
		return fmt.Sprintf("The one that failed had %s.", patterns[0])
	case len(patterns) == 1:
		return fmt.Sprintf("All %d that failed had %s.", total, patterns[0])
	}

	parts := make([]string, 0, shown+1)
	rest := total
	for _, p := range patterns[:min(shown, len(patterns))] {
		parts = append(parts, fmt.Sprintf("%d had %s", e[p], p))
		rest -= e[p]
	}

	if rest > 0 {
		parts = append(parts, fmt.Sprintf("%d had other results", rest))
	}

	return fmt.Sprintf("Of the %d that failed, %s.", total, strings.Join(parts, "; "))
}

// checkedAs describes the raw results on one failing row: "SPF pass for
// other.example (not aligned) and no DKIM signature". On a row that failed
// DMARC, a raw pass can only mean the domain checked does not align.
func checkedAs(o Observation) string {
	parts := make([]string, 0, len(o.SPFChecked)+len(o.DKIMChecked)+2)

	if len(o.SPFChecked) == 0 {
		parts = append(parts, "no SPF result")
	}
	for _, c := range o.SPFChecked {
		parts = append(parts, c.describe("SPF"))
	}

	if len(o.DKIMChecked) == 0 {
		parts = append(parts, "no DKIM signature")
	}
	for _, c := range o.DKIMChecked {
		parts = append(parts, c.describe("DKIM"))
	}

	return strings.Join(parts, " and ")
}

func (c Check) describe(mechanism string) string {
	domain := "an unnamed domain"
	if !c.Domain.IsZero() {
		domain = c.Domain.String()
	}

	text := fmt.Sprintf("%s %s for %s", mechanism, cmp.Or(c.Result, "with no result"), domain)
	if c.Selector != "" {
		text += ", selector " + c.Selector
	}
	if strings.EqualFold(c.Result, "pass") {
		text += " (not aligned)"
	}

	return text
}

// totals is one domain's arithmetic across every source.
type totals struct {
	volume  int
	passing int
	blocked int
	excused int
	policy  disposition.Disposition
}

func groupByDomain(obs []Observation) map[string][]Observation {
	byDomain := make(map[string][]Observation)
	for _, o := range obs {
		key := o.Domain.String()
		byDomain[key] = append(byDomain[key], o)
	}

	return byDomain
}

// groupBySource folds every observation for a domain into per-IP statistics,
// returned in a stable order — highest volume first — so that an alert reads
// worst-first and two runs over the same data produce the same email.
func groupBySource(obs []Observation) []sourceStats {
	bySource := make(map[netip.Addr]*sourceStats)

	for _, o := range obs {
		// Unaligned mail is somebody else's message that mentioned this domain
		// in passing — a forwarded newsletter, a bounce. Counting it would
		// blame this domain for another's configuration.
		if !o.Aligned {
			continue
		}

		s, ok := bySource[o.SourceIP]
		if !ok {
			s = &sourceStats{ip: o.SourceIP, known: o.KnownSource, firstEver: o.FirstEverReport, evidence: make(evidence)}
			bySource[o.SourceIP] = s
		}

		s.volume += o.Count
		s.policy = o.Policy

		switch {
		case o.Passed():
			s.passing += o.Count
		case o.Excused():
			s.excused += o.Count
		}

		if o.Blocked() {
			s.blocked += o.Count

			if o.Disposition == disposition.Reject {
				s.rejected += o.Count
			}

			if o.Org != "" && !slices.Contains(s.blockers, o.Org) {
				s.blockers = append(s.blockers, o.Org)
			}
		}

		if !o.Passed() {
			s.evidence.add(o)

			if !o.Blocked() && o.SampledOut() {
				s.sampled += o.Count
			}
		}

		if o.Org != "" && !slices.Contains(s.orgs, o.Org) {
			s.orgs = append(s.orgs, o.Org)
		}
	}

	stats := make([]sourceStats, 0, len(bySource))
	for _, s := range bySource {
		slices.Sort(s.orgs)
		slices.Sort(s.blockers)
		stats = append(stats, *s)
	}

	slices.SortFunc(stats, func(a, b sourceStats) int {
		if a.volume != b.volume {
			return b.volume - a.volume
		}

		return a.ip.Compare(b.ip)
	})

	return stats
}

func totalOf(obs []Observation) totals {
	var t totals

	for _, o := range obs {
		if !o.Aligned {
			continue
		}

		t.volume += o.Count
		t.policy = o.Policy

		switch {
		case o.Passed():
			t.passing += o.Count
		case o.Excused():
			t.excused += o.Count
		}

		if o.Blocked() {
			t.blocked += o.Count
		}
	}

	return t
}

func sourcesOf(obs []Observation) []netip.Addr {
	seen := make(map[netip.Addr]bool)
	for _, o := range obs {
		if o.Aligned {
			seen[o.SourceIP] = true
		}
	}

	return slices.Collect(maps.Keys(seen))
}

func reportersOf(obs []Observation) []string {
	seen := make(map[string]bool)
	for _, o := range obs {
		if o.Org != "" {
			seen[o.Org] = true
		}
	}

	return slices.Sorted(maps.Keys(seen))
}

// summarize is the arithmetic printed at the foot of every alert: what was
// looked at, so a short alert is visibly the result of a full look.
func summarize(obs []Observation) Summary {
	s := Summary{Reporters: reportersOf(obs)}

	reports := make(map[string]bool)
	domains := make(map[string]domainname.DomainName)

	for _, o := range obs {
		reports[o.ReportID] = true
		domains[o.Domain.String()] = o.Domain

		s.Volume += o.Count
		if o.Passed() {
			s.Passing += o.Count
		}
		if o.Blocked() {
			s.Blocked += o.Count
		}

		switch {
		case s.Window.Begin.IsZero(), o.Begin.Before(s.Window.Begin):
			s.Window.Begin = o.Begin
		}

		if o.End.After(s.Window.End) {
			s.Window.End = o.End
		}
	}

	s.Reports = len(reports)
	s.Domains = slices.SortedFunc(maps.Values(domains), func(a, b domainname.DomainName) int {
		return strings.Compare(a.String(), b.String())
	})

	return s
}

// share is part as a fraction of whole, or zero when there is no whole.
func share(part, whole int) float64 {
	if whole == 0 {
		return 0
	}

	return float64(part) / float64(whole)
}

// count is n with the noun that agrees with it: "1 message", "7 messages".
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}

	return strconv.Itoa(n) + " " + many
}

// were is the verb that agrees with n.
func were(n int) string {
	if n == 1 {
		return "was"
	}

	return "were"
}

// allOf is how the subject of "authenticated correctly" agrees with n.
func allOf(n int) string {
	if n == 1 {
		return "it"
	}

	return "they all"
}

// sentences joins the non-empty ones with a space.
func sentences(parts ...string) string {
	return strings.Join(slices.DeleteFunc(parts, func(p string) bool { return p == "" }), " ")
}

func percent(part, whole int) string {
	if whole == 0 {
		return "0%"
	}

	return fmt.Sprintf("%.1f%%", 100*float64(part)/float64(whole))
}
