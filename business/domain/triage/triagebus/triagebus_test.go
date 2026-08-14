package triagebus_test

import (
	"io"
	"log/slog"
	"net/netip"
	"slices"
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
