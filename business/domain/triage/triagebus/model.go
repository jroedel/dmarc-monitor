package triagebus

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jroedel/dmarc-monitor/business/types/authresult"
	"github.com/jroedel/dmarc-monitor/business/types/disposition"
	"github.com/jroedel/dmarc-monitor/business/types/domainname"
	"github.com/jroedel/dmarc-monitor/business/types/severity"
)

// Observation is one row of evidence: everything that happened to the messages
// one source sent for one domain during one report's window.
//
// It is deliberately this domain's own type rather than a report model. Triage
// must not import the report domain — composing the two is the App layer's job
// — and the narrowing is worth having on its own: the questions asked here are
// about volumes, sources and outcomes, and none of them need the DKIM selector
// or the reporter's contact address. A narrow input is also a cheap input to
// describe to a language model later.
type Observation struct {
	ReportID string
	Org      string
	Domain   domainname.DomainName
	Begin    time.Time
	End      time.Time

	// Policy is what the receiver was asked to do with failing mail. It decides
	// whether a failure costs anything: the same numbers under p=none and
	// p=reject are a warning and an outage respectively.
	Policy disposition.Disposition

	SourceIP    netip.Addr
	Count       int
	Disposition disposition.Disposition
	DKIM        authresult.AuthResult
	SPF         authresult.AuthResult
	HeaderFrom  domainname.DomainName

	// Aligned is whether the header-from domain aligned with the policy domain.
	// Unaligned mail in a report is usually somebody else's message that
	// happened to be forwarded; it is not evidence about this domain's setup.
	Aligned bool

	// Overrides are the receiver's stated reasons for departing from policy.
	// A "forwarded" or "mailing_list" override is the single strongest signal
	// that a failure is expected and uninteresting.
	Overrides []string

	// SPFChecked and DKIMChecked are the receiver's raw results, before
	// alignment: which domain each mechanism was checked against, and what
	// came back. They decide nothing. They are what a finding quotes, because
	// "DMARC failed" is not actionable and "SPF passed for another domain and
	// there was no DKIM signature" is.
	SPFChecked  []Check
	DKIMChecked []Check

	// KnownSource is whether this IP has sent for this domain before, according
	// to the checkpoint. Supplied by the App layer, because remembering across
	// runs is not something a Business domain should own.
	KnownSource bool

	// FirstEverReport is whether the checkpoint had nothing at all for this
	// domain. On a first run every source is new, and calling all of them new
	// would produce one enormous, useless alert.
	FirstEverReport bool
}

// Passed reports whether the messages satisfied DMARC.
func (o Observation) Passed() bool { return o.DKIM.Passed() || o.SPF.Passed() }

// Blocked reports whether the receiver withheld the messages from the inbox.
func (o Observation) Blocked() bool { return !o.Disposition.Delivered() }

// Check is one raw authentication result from a report's <auth_results>.
// Result is the receiver's own word — pass, fail, softfail, none, temperror —
// and deliberately not an authresult: that type is the aligned, binary
// verdict, and this is the evidence behind it.
type Check struct {
	Domain   domainname.DomainName
	Selector string // DKIM only
	Result   string
}

// excuses are the overrides that explain a failure: the mail was relayed by
// something that breaks authentication as a matter of course. The other
// overrides say the receiver did not apply the policy, not that the failure
// was expected — sampled_out above all, which only means pct= let the
// message through this time.
var excuses = []string{"forwarded", "trusted_forwarder", "mailing_list"}

// Excused reports whether the receiver said why these messages were expected
// to fail: forwarding or a mailing list.
func (o Observation) Excused() bool { return o.overridden(excuses...) }

// SampledOut reports whether the receiver skipped the policy for these
// messages only because the policy's pct= told it to. Failing mail that was
// sampled out is mail that a pct=100 would have blocked.
func (o Observation) SampledOut() bool { return o.overridden("sampled_out") }

func (o Observation) overridden(types ...string) bool {
	return slices.ContainsFunc(o.Overrides, func(got string) bool {
		return slices.ContainsFunc(types, func(want string) bool { return strings.EqualFold(got, want) })
	})
}

// Finding is one thing worth saying to a human, already graded.
type Finding struct {
	Severity severity.Severity

	// Code is a stable slug identifying the kind of finding. It is half the
	// fingerprint and it must not change casually: changing it makes every
	// existing finding look new and re-alerts on all of them.
	Code string

	Domain   domainname.DomainName
	Headline string

	// Detail is the evidence, in whole sentences. This is what a webmaster
	// reads at 8am; it should be possible to act on without opening the report.
	Detail string

	// Action is the one thing to do about it. A finding with no action is a
	// finding that should not have been sent.
	Action string

	// Subject narrows the fingerprint below the domain — a source IP, usually —
	// so that a second misbehaving sender is a new alert rather than a repeat.
	Subject string

	Volume int
}

// Fingerprint identifies the finding across runs, for cooldown purposes. It is
// deliberately readable: an operator debugging a missing alert can find it by
// eye in the state file.
func (f Finding) Fingerprint() string {
	if f.Subject == "" {
		return fmt.Sprintf("%s|%s", f.Code, f.Domain)
	}

	return fmt.Sprintf("%s|%s|%s", f.Code, f.Domain, f.Subject)
}

// Summary is the arithmetic behind the findings: what was looked at, so that a
// quiet result is visibly a quiet result rather than a run that did nothing.
type Summary struct {
	Reports   int
	Domains   []domainname.DomainName
	Reporters []string
	Volume    int
	Passing   int
	Blocked   int
	Window    Window
}

// Window is the span the reports covered.
type Window struct {
	Begin time.Time
	End   time.Time
}

// PassRate is the fraction of messages that satisfied DMARC, or zero when
// nothing was seen.
func (s Summary) PassRate() float64 {
	if s.Volume == 0 {
		return 0
	}

	return float64(s.Passing) / float64(s.Volume)
}

// Verdict is the outcome of triage.
type Verdict struct {
	Severity severity.Severity
	Findings []Finding
	Summary  Summary

	// Narrative is the optional plain-English framing written by an Explainer.
	// It is never the basis of a decision — every field above is already
	// settled by the time it is asked for — so an absent or wrong narrative
	// costs prose, not correctness.
	Narrative string
}

// NewVerdict assembles a verdict, grading it at the severity of its loudest
// finding. Exported because the App layer drops findings that are still inside
// their cooldown and must be able to re-grade what remains.
func NewVerdict(findings []Finding, summary Summary) Verdict {
	v := Verdict{Findings: findings, Summary: summary}

	// Worst first, and among equals the one that names a culprit first. The
	// leading finding becomes the subject line, and "mail from 198.51.100.7 is
	// being blocked" is something a webmaster can act on from their phone;
	// "22% of mail is failing DMARC" sends them looking for the reason. Volume
	// only breaks the remaining ties.
	slices.SortStableFunc(v.Findings, func(a, b Finding) int {
		if c := severity.Compare(b.Severity, a.Severity); c != 0 {
			return c
		}

		if c := named(b) - named(a); c != 0 {
			return c
		}

		return b.Volume - a.Volume
	})

	for _, f := range v.Findings {
		if severity.Compare(f.Severity, v.Severity) > 0 {
			v.Severity = f.Severity
		}
	}

	return v
}

// named reports whether a finding points at a specific source, as a sort key.
func named(f Finding) int {
	if f.Subject == "" {
		return 0
	}

	return 1
}

// Actionable reports whether the verdict reaches the floor at which a human is
// worth disturbing.
func (v Verdict) Actionable(floor severity.Severity) bool {
	return len(v.Findings) > 0 && v.Severity.AtLeast(floor)
}
