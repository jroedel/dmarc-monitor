package triagebus_test

import (
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jroedel/dmarc-monitor/business/domain/triage/triagebus"
	"github.com/jroedel/dmarc-monitor/business/types/authresult"
	"github.com/jroedel/dmarc-monitor/business/types/disposition"
	"github.com/jroedel/dmarc-monitor/business/types/domainname"
	"github.com/jroedel/dmarc-monitor/business/types/severity"
)

// These tests are the specification for when a human gets disturbed. Each one
// is a case that was either worth an email or worth silence, and the silent
// ones matter most: a monitor that cries wolf is a monitor nobody reads.

func newBusiness() *triagebus.Business {
	return triagebus.NewBusiness(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		triagebus.Thresholds{FailureRate: 0.02, MinimumVolume: 25, NewSourceVolume: 50},
		nil,
	)
}

type obsOption func(*triagebus.Observation)

func observation(ip string, count int, opts ...obsOption) triagebus.Observation {
	o := triagebus.Observation{
		ReportID:    "report-1",
		Org:         "google.com",
		Domain:      domainname.MustParse("example.com"),
		Begin:       time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC),
		End:         time.Date(2026, 8, 13, 23, 59, 59, 0, time.UTC),
		Policy:      disposition.None,
		SourceIP:    netip.MustParseAddr(ip),
		Count:       count,
		Disposition: disposition.None,
		DKIM:        authresult.Pass,
		SPF:         authresult.Pass,
		HeaderFrom:  domainname.MustParse("example.com"),
		Aligned:     true,
		KnownSource: true,
	}

	for _, opt := range opts {
		opt(&o)
	}

	return o
}

func failing(o *triagebus.Observation) {
	o.DKIM = authresult.Fail
	o.SPF = authresult.Fail
}

func rejected(o *triagebus.Observation) {
	o.Disposition = disposition.Reject
	o.Policy = disposition.Reject
}

func unknownSource(o *triagebus.Observation) { o.KnownSource = false }

// enforcing puts the domain on p=quarantine, which is where a domain that has
// finished its DMARC rollout lives. Several rules only fire under p=none, so a
// test about anything else has to say which world it is in.
func enforcing(o *triagebus.Observation) { o.Policy = disposition.Quarantine }

func codes(v triagebus.Verdict) []string {
	out := make([]string, 0, len(v.Findings))
	for _, f := range v.Findings {
		out = append(out, f.Code)
	}

	return out
}

func assess(t *testing.T, obs []triagebus.Observation) triagebus.Verdict {
	t.Helper()

	v, err := newBusiness().Assess(t.Context(), obs)
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}

	return v
}

// The common case by a wide margin: everything authenticates, nothing is
// blocked, and the program must say nothing at all.
func TestQuietTrafficProducesNothing(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("203.0.113.10", 500, enforcing),
		observation("203.0.113.11", 120, enforcing),
	})

	if len(v.Findings) != 0 {
		t.Errorf("clean traffic produced findings: %v", codes(v))
	}
}

// A little failure is normal — forwarding breaks SPF every day — and must stay
// under the threshold rather than generating a daily email.
func TestFailureBelowThresholdIsSilent(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("203.0.113.10", 1000, enforcing),
		observation("203.0.113.10", 10, failing, enforcing),
	})

	if len(v.Findings) != 0 {
		t.Errorf("1%% failure produced findings: %v", codes(v))
	}
}

// The reason the program exists: a server this domain has used before is having
// its mail rejected. Nothing else in the system may outrank this.
func TestBlockedKnownSourceIsCritical(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("203.0.113.10", 400),
		observation("198.51.100.7", 90, failing, rejected),
	})

	if !slices.Contains(codes(v), "blocked-known-source") {
		t.Fatalf("no blocked-known-source finding; got %v", codes(v))
	}
	if v.Severity != severity.Critical {
		t.Errorf("severity = %s, want critical", v.Severity)
	}

	first := v.Findings[0]
	switch {
	case first.Severity != severity.Critical:
		t.Errorf("worst finding is not first: %s", first.Severity)
	case first.Subject != "198.51.100.7":
		t.Errorf("finding subject = %q, want the offending IP", first.Subject)
	case first.Action == "":
		t.Error("a critical finding with no action is not actionable")
	}
}

// The same problem one stage earlier, while p=none means nothing is lost yet.
// This is the alert that saves the work, so it must fire.
func TestFailingKnownSourceUnderNoneIsWarning(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("198.51.100.7", 60, failing),
	})

	if !slices.Contains(codes(v), "failing-known-source") {
		t.Fatalf("no failing-known-source finding; got %v", codes(v))
	}
	if v.Severity != severity.Warning {
		t.Errorf("severity = %s, want warning", v.Severity)
	}
}

// A receiver that tells us it forwarded the message has explained the failure.
// Alerting on it anyway is how a monitor teaches people to ignore it.
func TestExcusedFailuresAreSilent(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("198.51.100.7", 200, failing, func(o *triagebus.Observation) {
			o.Overrides = []string{"forwarded"}
		}),
	})

	if len(v.Findings) != 0 {
		t.Errorf("receiver-excused failures produced findings: %v", codes(v))
	}
}

func TestNewSourceAtVolumeIsNoticed(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("203.0.113.10", 400, enforcing),
		observation("192.0.2.99", 120, unknownSource, enforcing),
	})

	if !slices.Contains(codes(v), "new-source") {
		t.Fatalf("no new-source finding; got %v", codes(v))
	}
}

// On the first run every sender is new. Reporting all of them would produce one
// enormous alert that says nothing, and would train the reader to delete it.
func TestFirstEverRunDoesNotReportNewSources(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("192.0.2.99", 400, unknownSource, enforcing, func(o *triagebus.Observation) {
			o.FirstEverReport = true
		}),
	})

	if slices.Contains(codes(v), "new-source") {
		t.Errorf("first run reported new sources: %v", codes(v))
	}
}

// A small new sender is not news. The volume threshold is what keeps a monthly
// password-reset relay out of the alert.
func TestSmallNewSourceIsSilent(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("192.0.2.99", 3, unknownSource, enforcing),
	})

	if len(v.Findings) != 0 {
		t.Errorf("a 3-message new sender produced findings: %v", codes(v))
	}
}

// Unaligned mail is another domain's message that merely passed through. Its
// failures are not this domain's problem and must not be counted against it.
func TestUnalignedMailIsIgnored(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("198.51.100.7", 900, failing, enforcing, func(o *triagebus.Observation) {
			o.Aligned = false
			o.HeaderFrom = domainname.MustParse("someone-else.example")
		}),
	})

	if len(v.Findings) != 0 {
		t.Errorf("unaligned mail produced findings about our domain: %v", codes(v))
	}
}

// The one piece of good news the program delivers, and the one nobody notices
// for themselves: clean mail at volume, still on a policy that protects nothing.
func TestReadyToEnforce(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("203.0.113.10", 400),
		observation("203.0.113.11", 300),
	})

	if !slices.Contains(codes(v), "ready-to-enforce") {
		t.Fatalf("no ready-to-enforce finding; got %v", codes(v))
	}
	if v.Severity != severity.Notice {
		t.Errorf("severity = %s, want notice", v.Severity)
	}
}

// A notice must not reach a webmaster whose floor is warning.
func TestFloorSuppressesLowSeverity(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("203.0.113.10", 400),
		observation("203.0.113.11", 300),
	})

	if v.Actionable(severity.Warning) {
		t.Error("a notice-level verdict was actionable at the warning floor")
	}
	if !v.Actionable(severity.Notice) {
		t.Error("a notice-level verdict was not actionable at the notice floor")
	}
}

// The fingerprint is what the cooldown keys on. Two runs over the same problem
// must produce the same string, and two different sources must not collide.
func TestFingerprintStability(t *testing.T) {
	obs := []triagebus.Observation{
		observation("203.0.113.10", 400),
		observation("198.51.100.7", 90, failing, rejected),
		observation("198.51.100.8", 90, failing, rejected),
	}

	first := assess(t, obs)
	second := assess(t, obs)

	if len(first.Findings) != len(second.Findings) {
		t.Fatalf("two runs produced %d and %d findings", len(first.Findings), len(second.Findings))
	}

	seen := make(map[string]bool)
	for i := range first.Findings {
		a, b := first.Findings[i].Fingerprint(), second.Findings[i].Fingerprint()
		if a != b {
			t.Errorf("fingerprint changed between runs: %q then %q", a, b)
		}
		if seen[a] {
			t.Errorf("two findings share the fingerprint %q; one would silence the other", a)
		}
		seen[a] = true
	}
}

// Summary is what the alert's footer is built from, and what a reader uses to
// decide whether the program actually looked at anything.
func TestSummaryArithmetic(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("203.0.113.10", 400),
		observation("198.51.100.7", 100, failing, rejected),
	})

	s := v.Summary
	switch {
	case s.Volume != 500:
		t.Errorf("volume = %d, want 500", s.Volume)
	case s.Passing != 400:
		t.Errorf("passing = %d, want 400", s.Passing)
	case s.Blocked != 100:
		t.Errorf("blocked = %d, want 100", s.Blocked)
	case s.Reports != 1:
		t.Errorf("reports = %d, want 1", s.Reports)
	case len(s.Domains) != 1:
		t.Errorf("domains = %v, want one", s.Domains)
	}

	if got, want := s.PassRate(), 0.8; got != want {
		t.Errorf("pass rate = %v, want %v", got, want)
	}
}

// unsigned is mail that SPF-passed for a different domain and carried no DKIM
// signature: what a web application sends when it uses its own hosting
// account's address as the envelope sender and nothing signs for the domain.
func unsigned(o *triagebus.Observation) {
	failing(o)
	o.SPFChecked = []triagebus.Check{{Domain: domainname.MustParse("hosting.example"), Result: "pass"}}
}

func quarantined(o *triagebus.Observation) { o.Disposition = disposition.Quarantine }

func sampledOut(o *triagebus.Observation) { o.Overrides = []string{"sampled_out"} }

func finding(t *testing.T, v triagebus.Verdict, code string) triagebus.Finding {
	t.Helper()

	i := slices.IndexFunc(v.Findings, func(f triagebus.Finding) bool { return f.Code == code })
	if i < 0 {
		t.Fatalf("no %s finding; got %v", code, codes(v))
	}

	return v.Findings[i]
}

func mustContain(t *testing.T, field, got string, wants ...string) {
	t.Helper()

	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Errorf("%s does not say %q:\n%s", field, want, got)
		}
	}
}

// A receiver that skipped the policy because pct= told it to has not
// explained anything: at pct=100 the same messages are blocked. A known
// server whose failing mail all happened to be sampled out must not go quiet.
func TestSampledOutFailuresAreNotExcused(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("198.51.100.7", 60, unsigned, enforcing, sampledOut),
	})

	f := finding(t, v, "failing-known-source")
	if f.Severity != severity.Warning {
		t.Errorf("severity = %s, want warning", f.Severity)
	}

	// The domain is already enforcing, so "before it moves to quarantine"
	// would be advice about a step already taken.
	mustContain(t, "detail", f.Detail, "delivered only because the policy's pct= sampling skipped it this time")
	if strings.Contains(f.Action, "moves to quarantine") {
		t.Errorf("action assumes p=none on an enforcing domain: %s", f.Action)
	}
}

// Every receiver that saw a server reports it; only some of them blocked it.
// Naming the wrong one sends the webmaster to the wrong postmaster page.
func TestBlockedNamesTheReceiverThatBlocked(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("198.51.100.7", 100, enforcing, func(o *triagebus.Observation) { o.Org = "Outlook.com" }),
		observation("198.51.100.7", 100, enforcing),
		observation("198.51.100.7", 10, unsigned, enforcing, quarantined),
	})

	f := finding(t, v, "blocked-known-source")
	mustContain(t, "detail", f.Detail, "and google.com quarantined 10 of them.")
}

// One sender that is not named — first report ever, or too little mail to
// judge — is not a domain-wide pattern, and must not be described as one.
func TestDomainWideFailureFromOneUnnamedSender(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("198.51.100.7", 19, enforcing, unknownSource),
		observation("198.51.100.7", 7, unsigned, enforcing, sampledOut, unknownSource),
	})

	f := finding(t, v, "domain-failure-rate")
	mustContain(t, "detail", f.Detail, "7 of 26 messages failed DMARC and 0 were blocked, all of them from 198.51.100.7")
	if strings.Contains(f.Detail, "record is wrong") {
		t.Errorf("one sender described as a domain-wide record problem:\n%s", f.Detail)
	}
}

// The shape of a real day: one server sends most of its mail correctly and a
// small stream unsigned, under p=quarantine with pct=25, so the receiver
// quarantines a quarter of the stream and delivers the rest by sampling. The
// alert must say how much failed, how much got through only by luck, and what
// the receiver saw — and say it once, not again as a domain-wide finding that
// claims no sender is responsible.
func TestBlockedSourceExplainsItself(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("198.51.100.7", 31, enforcing),
		observation("198.51.100.7", 2, unsigned, enforcing, quarantined),
		observation("198.51.100.7", 5, unsigned, enforcing, sampledOut),
		observation("203.0.113.41", 6, enforcing),
	})

	if got := codes(v); !slices.Equal(got, []string{"blocked-known-source"}) {
		t.Fatalf("findings = %v, want only blocked-known-source", got)
	}

	f := v.Findings[0]
	if f.Severity != severity.Critical {
		t.Errorf("severity = %s, want critical: 7 of 38 failing is well over the threshold", f.Severity)
	}

	mustContain(t, "headline", f.Headline, "Mail from 198.51.100.7 is being blocked")
	mustContain(t, "detail", f.Detail,
		"7 of its 38 messages in this reporting window failed DMARC, and google.com quarantined 2 of them.",
		"Another 5 were delivered only because the policy's pct= sampling skipped them",
		"All 7 that failed had SPF pass for hosting.example (not aligned) and no DKIM signature.")
}

// Severity follows how much of a server's mail fails, so one quarantined
// message among a thousand clean ones is still reported, but as what it is.
func TestOneBlockedMessageAmongManyIsAWarning(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("198.51.100.7", 1000, enforcing),
		observation("198.51.100.7", 1, unsigned, enforcing, quarantined),
	})

	f := finding(t, v, "blocked-known-source")
	if f.Severity != severity.Warning {
		t.Errorf("severity = %s, want warning", f.Severity)
	}

	mustContain(t, "headline", f.Headline, "1 message from 198.51.100.7 was quarantined")
	mustContain(t, "detail", f.Detail, "The one that failed had SPF pass for hosting.example (not aligned) and no DKIM signature.")
}

// With no sender bad enough to name, the domain-wide finding is the only
// signal, and the receiver's results are what point at the record to check.
func TestDomainWideFailureWithoutANamedSender(t *testing.T) {
	var obs []triagebus.Observation
	for i := range 6 {
		ip := netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i)}).String()
		obs = append(obs,
			observation(ip, 20, enforcing),
			observation(ip, 3, enforcing, failing, func(o *triagebus.Observation) {
				o.DKIMChecked = []triagebus.Check{{Domain: domainname.MustParse("example.com"), Selector: "s2024", Result: "fail"}}
				o.SPFChecked = []triagebus.Check{{Domain: domainname.MustParse("example.com"), Result: "permerror"}}
			}))
	}

	v := assess(t, obs)

	f := finding(t, v, "domain-failure-rate")
	mustContain(t, "detail", f.Detail,
		"18 of 138 messages failed DMARC and 0 were blocked, spread across 6 senders, none failing enough to be named on its own.",
		"All 18 that failed had SPF permerror for example.com and DKIM fail for example.com, selector s2024.")
}

// When a sender is already named, the domain-wide finding speaks only for
// what is left, and only if what is left is itself over the threshold.
func TestDomainWideFailureCountsOnlyWhatIsUnexplained(t *testing.T) {
	obs := []triagebus.Observation{
		observation("198.51.100.7", 100, enforcing),
		observation("198.51.100.7", 20, unsigned, enforcing, quarantined),
	}
	for i := range 5 {
		ip := netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i)}).String()
		obs = append(obs, observation(ip, 2, enforcing, failing))
	}

	v := assess(t, obs)

	f := finding(t, v, "domain-failure-rate")
	mustContain(t, "headline", f.Headline, "Another 7.7% of mail claiming example.com is failing DMARC")
	mustContain(t, "detail", f.Detail,
		"Apart from the senders above, 10 of the domain's 130 messages failed DMARC and 0 were blocked, from 5 other senders.")

	if strings.Contains(f.Detail, "none failing enough") {
		t.Errorf("detail claims no sender is named, after one was:\n%s", f.Detail)
	}
}

// Several stories at once are told most common first, and the tail is
// counted rather than dropped.
func TestFailureEvidenceListsTheCommonPatterns(t *testing.T) {
	other := func(name string) obsOption {
		return func(o *triagebus.Observation) {
			o.DKIMChecked = []triagebus.Check{{Domain: domainname.MustParse(name), Selector: "k1", Result: "pass"}}
		}
	}

	v := assess(t, []triagebus.Observation{
		observation("198.51.100.7", 100),
		observation("198.51.100.7", 6, unsigned),
		observation("198.51.100.7", 3, failing, other("a.example")),
		observation("198.51.100.7", 2, failing, other("b.example")),
		observation("198.51.100.7", 1, failing, other("c.example")),
	})

	f := finding(t, v, "failing-known-source")
	mustContain(t, "detail", f.Detail,
		"Of the 12 that failed, 6 had SPF pass for hosting.example (not aligned) and no DKIM signature; "+
			"3 had no SPF result and DKIM pass for a.example, selector k1 (not aligned); "+
			"2 had no SPF result and DKIM pass for b.example, selector k1 (not aligned); "+
			"1 had other results.")
}

// The action is the line a webmaster acts on. When the failing mail tells one
// story, it must name the change that story calls for, not send the reader
// back to the report to work it out.
func TestActionNamesTheFixTheEvidenceCallsFor(t *testing.T) {
	ours := domainname.MustParse("example.com")
	other := domainname.MustParse("hosting.example")

	tests := map[string]struct {
		spf, dkim []triagebus.Check
		want      string
	}{
		"return address at another domain, unsigned": {
			spf:  []triagebus.Check{{Domain: other, Result: "pass"}},
			want: "The failing mail uses a return address at hosting.example, so SPF passes for that domain and cannot count for example.com, and nothing signs it with DKIM. Give the sender a return address at example.com, or have it sign with a DKIM key published for example.com.",
		},
		"signature that does not verify": {
			spf:  []triagebus.Check{{Domain: other, Result: "pass"}},
			dkim: []triagebus.Check{{Domain: ours, Selector: "s2024", Result: "fail"}},
			want: "The failing mail carries a DKIM signature for example.com that does not verify (fail). Check that s2024._domainkey.example.com is published and holds the key the sender signs with.",
		},
		"broken SPF record": {
			spf:  []triagebus.Check{{Domain: ours, Result: "permerror"}},
			want: "The SPF record for example.com returns permerror. Look for more than ten DNS lookups, or an include that no longer resolves.",
		},
		"signed by the service, not the domain": {
			spf:  []triagebus.Check{{Domain: other, Result: "pass"}},
			dkim: []triagebus.Check{{Domain: other, Selector: "k1", Result: "pass"}},
			want: "The failing mail is signed with a DKIM key for hosting.example, which does not count for example.com. Set the sender up to sign as example.com, by publishing the DKIM record it provides under example.com.",
		},
		"server missing from SPF": {
			spf:  []triagebus.Check{{Domain: ours, Result: "softfail"}},
			want: "The failing mail gets SPF softfail for example.com and carries no DKIM signature. Add the sending server to the SPF record for example.com, or sign its mail with a DKIM key published for example.com.",
		},
		"nothing to go on": {
			want: "Add 198.51.100.7 to the SPF record, or sign its mail with a DKIM key published for example.com.",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			v := assess(t, []triagebus.Observation{
				observation("198.51.100.7", 100),
				observation("198.51.100.7", 60, failing, func(o *triagebus.Observation) {
					o.SPFChecked = tt.spf
					o.DKIMChecked = tt.dkim
				}),
			})

			f := finding(t, v, "failing-known-source")
			mustContain(t, "action", f.Action, "Fix this before example.com moves to quarantine or reject.", tt.want)
		})
	}
}

// Advice drawn from one pattern is wrong for mail failing several ways at
// once, so below half the generic advice stands; at a majority, it says so.
func TestActionNeedsAMajorityPattern(t *testing.T) {
	unsignedFrom := func(name string) obsOption {
		return func(o *triagebus.Observation) {
			failing(o)
			o.SPFChecked = []triagebus.Check{{Domain: domainname.MustParse(name), Result: "pass"}}
		}
	}

	split := assess(t, []triagebus.Observation{
		observation("198.51.100.7", 100),
		observation("198.51.100.7", 20, unsignedFrom("a.example")),
		observation("198.51.100.7", 20, unsignedFrom("b.example")),
		observation("198.51.100.7", 20, unsignedFrom("c.example")),
	})
	mustContain(t, "action", finding(t, split, "failing-known-source").Action, "Add 198.51.100.7 to the SPF record")

	most := assess(t, []triagebus.Observation{
		observation("198.51.100.7", 100),
		observation("198.51.100.7", 40, unsignedFrom("a.example")),
		observation("198.51.100.7", 20, unsignedFrom("b.example")),
	})
	mustContain(t, "action", finding(t, most, "failing-known-source").Action, "Most of the failing mail uses a return address at a.example")
}

// A blocked server's action keeps both halves: the fix if it is ours, and
// what it means if it is not.
func TestBlockedActionNamesTheFix(t *testing.T) {
	v := assess(t, []triagebus.Observation{
		observation("198.51.100.7", 31, enforcing),
		observation("198.51.100.7", 7, unsigned, enforcing, quarantined),
	})

	mustContain(t, "action", finding(t, v, "blocked-known-source").Action,
		"If 198.51.100.7 is one of ours: The failing mail uses a return address at hosting.example",
		"If it is not ours, someone is sending as example.com and DMARC is correctly stopping them.")
}
