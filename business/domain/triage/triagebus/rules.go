package triagebus

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
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

	var findings []Finding

	findings = append(findings, b.blockedKnownSources(domain, sources)...)
	findings = append(findings, b.failingKnownSources(domain, sources)...)
	findings = append(findings, b.newSources(domain, sources)...)

	if f, ok := b.domainWideFailure(domain, totals, obs); ok {
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
func (b *Business) blockedKnownSources(domain domainname.DomainName, sources []sourceStats) []Finding {
	var findings []Finding

	for _, s := range sources {
		switch {
		case s.blocked == 0, !s.known, s.excused == s.volume:
			continue
		}

		findings = append(findings, Finding{
			Severity: severity.Critical,
			Code:     "blocked-known-source",
			Domain:   domain,
			Subject:  s.ip.String(),
			Volume:   s.blocked,
			Headline: fmt.Sprintf("Mail from %s is being blocked", s.ip),
			Detail: fmt.Sprintf(
				"%s has sent mail for %s before, but %d of its %d messages in this reporting window were %s by %s. "+
					"%s. This is mail that did not reach the recipient.",
				s.ip, domain, s.blocked, s.volume, s.blockedVerb(), s.orgList(), s.authSummary()),
			Action: fmt.Sprintf(
				"Check what %s is: if it is one of ours, its SPF entry or DKIM key has probably changed or expired. "+
					"If it is not ours, someone is sending as %s and DMARC is correctly stopping them.",
				s.ip, domain),
		})
	}

	return findings
}

// failingKnownSources catches the same problem one stage earlier: a known
// sender failing authentication while the published policy still lets the mail
// through. This is the window in which the fix costs nothing, which is exactly
// why it is worth an email.
func (b *Business) failingKnownSources(domain domainname.DomainName, sources []sourceStats) []Finding {
	var findings []Finding

	for _, s := range sources {
		failing := s.volume - s.passing

		switch {
		case !s.known, s.blocked > 0, failing == 0:
			continue
		case s.volume < b.thresholds.MinimumVolume:
			continue
		case float64(failing)/float64(s.volume) < b.thresholds.FailureRate:
			continue
		case s.excused == failing:
			// Every failure was one the receiver told us to expect.
			continue
		}

		findings = append(findings, Finding{
			Severity: severity.Warning,
			Code:     "failing-known-source",
			Domain:   domain,
			Subject:  s.ip.String(),
			Volume:   failing,
			Headline: fmt.Sprintf("%s is failing authentication for %s", s.ip, domain),
			Detail: fmt.Sprintf(
				"%d of %d messages (%s) from %s failed DMARC, reported by %s. %s. "+
					"The published policy is p=%s, so the mail was still delivered — for now.",
				failing, s.volume, percent(failing, s.volume), s.ip, s.orgList(), s.authSummary(), s.policy),
			Action: fmt.Sprintf(
				"Fix this before %s moves to quarantine or reject: add %s to the SPF record, or sign its mail with a DKIM key published for %s.",
				domain, s.ip, domain),
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
			"%s sent %d messages as %s and they all authenticated correctly. It has not appeared in any earlier report.",
			s.ip, s.volume, domain)

		if s.passing < s.volume {
			level = severity.Warning
			detail = fmt.Sprintf(
				"%s sent %d messages as %s, of which %d failed DMARC. It has not appeared in any earlier report. %s.",
				s.ip, s.volume, domain, s.volume-s.passing, s.authSummary())
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
func (b *Business) domainWideFailure(domain domainname.DomainName, t totals, obs []Observation) (Finding, bool) {
	failing := t.volume - t.passing

	switch {
	case t.volume < b.thresholds.MinimumVolume, failing == 0:
		return Finding{}, false
	case float64(failing)/float64(t.volume) < b.thresholds.FailureRate:
		return Finding{}, false
	case t.excused == failing:
		return Finding{}, false
	}

	level := severity.Warning
	if t.blocked > 0 {
		level = severity.Critical
	}

	return Finding{
		Severity: level,
		Code:     "domain-failure-rate",
		Domain:   domain,
		Volume:   failing,
		Headline: fmt.Sprintf("%s of mail claiming %s is failing DMARC", percent(failing, t.volume), domain),
		Detail: fmt.Sprintf(
			"Across %d reporting sources, %d of %d messages failed DMARC and %d were blocked. "+
				"No single sender is responsible, which usually means the domain's own SPF or DKIM record is wrong rather than one server being misconfigured.",
			len(reportersOf(obs)), failing, t.volume, t.blocked),
		Action: fmt.Sprintf(
			"Check the current SPF and DKIM records for %s — an include that stopped resolving, or a selector that no longer exists, produces exactly this pattern.",
			domain),
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

	dkimPassed int
	spfPassed  int
}

// blockedVerb describes what actually happened, since "blocked" is not what an
// operator will see in their own logs.
func (s sourceStats) blockedVerb() string {
	if s.rejected == s.blocked {
		return "rejected"
	}

	return "quarantined or rejected"
}

func (s sourceStats) orgList() string {
	switch len(s.orgs) {
	case 0:
		return "the reporting receivers"
	case 1:
		return s.orgs[0]
	default:
		return fmt.Sprintf("%s and %d other receivers", s.orgs[0], len(s.orgs)-1)
	}
}

// authSummary says which mechanism failed, which is the first thing anyone
// investigating needs and the last thing a raw report makes obvious.
func (s sourceStats) authSummary() string {
	switch {
	case s.dkimPassed == 0 && s.spfPassed == 0:
		return "Neither SPF nor DKIM aligned"
	case s.dkimPassed == 0:
		return "DKIM did not align; SPF carried what passed"
	case s.spfPassed == 0:
		return "SPF did not align; DKIM carried what passed"
	default:
		return "Both mechanisms passed on some messages and not others"
	}
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
			s = &sourceStats{ip: o.SourceIP, known: o.KnownSource, firstEver: o.FirstEverReport}
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
		}

		if o.DKIM.Passed() {
			s.dkimPassed += o.Count
		}
		if o.SPF.Passed() {
			s.spfPassed += o.Count
		}

		if o.Org != "" && !slices.Contains(s.orgs, o.Org) {
			s.orgs = append(s.orgs, o.Org)
		}
	}

	stats := make([]sourceStats, 0, len(bySource))
	for _, s := range bySource {
		slices.Sort(s.orgs)
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

func percent(part, whole int) string {
	if whole == 0 {
		return "0%"
	}

	return fmt.Sprintf("%.1f%%", 100*float64(part)/float64(whole))
}
