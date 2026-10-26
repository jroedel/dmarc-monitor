package triagebus

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/jroedel/dmarc-monitor/business/types/domainname"
)

// A finding that says "check SPF and DKIM" sends the reader to the reports to
// find out which, and that is the job this program exists to do. When the
// failing mail mostly tells one story, the receiver's raw results already say
// what is broken, and the action can say what to change.
//
// The remedies here only reword advice. They decide nothing: which findings
// exist, and how severe they are, is settled before any of this runs.

// remedy is the specific fix for the pattern behind most of the failing mail,
// or false when no pattern covers at least half of it or none has a fix more
// specific than the generic one.
func remedy(domain domainname.DomainName, e evidence) (string, bool) {
	patterns := e.sorted()
	if len(patterns) == 0 || 2*patterns[0].n < e.total() {
		return "", false
	}

	p := patterns[0]

	subject := "The failing mail"
	if p.n < e.total() {
		subject = "Most of the failing mail"
	}

	ours := func(c Check) bool { return c.Domain.Aligns(domain, false) }
	passed := func(c Check) bool { return strings.EqualFold(c.Result, "pass") }

	// What the pattern holds, one check of each kind. The converter drops a
	// check whose domain does not parse, so a zero Domain means "none".
	var seen struct {
		brokenDKIM, otherDKIM, brokenSPFRecord, missedSPF, otherSPF Check
	}

	for _, c := range p.dkim {
		switch {
		case ours(c) && !passed(c):
			seen.brokenDKIM = c
		case !ours(c) && passed(c):
			seen.otherDKIM = c
		}
	}

	for _, c := range p.spf {
		result := strings.ToLower(c.Result)

		switch {
		case ours(c) && (result == "permerror" || result == "temperror"):
			seen.brokenSPFRecord = c
		case ours(c) && !passed(c):
			seen.missedSPF = c
		case !ours(c) && passed(c):
			seen.otherSPF = c
		}
	}

	// Most specific first: a signature that exists but does not verify is a
	// key problem whatever SPF did, and a broken SPF record breaks every
	// sender at once.
	switch {
	case !seen.brokenDKIM.Domain.IsZero():
		c := seen.brokenDKIM

		where := "the DKIM record the sender signs with"
		if c.Selector != "" {
			where = fmt.Sprintf("%s._domainkey.%s", c.Selector, c.Domain)
		}

		return fmt.Sprintf(
			"%s carries a DKIM signature for %s that does not verify (%s). Check that %s is published and holds the key the sender signs with.",
			subject, c.Domain, strings.ToLower(c.Result), where), true

	case !seen.brokenSPFRecord.Domain.IsZero():
		c := seen.brokenSPFRecord

		return fmt.Sprintf(
			"The SPF record for %s returns %s. Look for more than ten DNS lookups, or an include that no longer resolves.",
			c.Domain, strings.ToLower(c.Result)), true

	case !seen.otherSPF.Domain.IsZero() && len(p.dkim) == 0:
		return fmt.Sprintf(
			"%s uses a return address at %s, so SPF passes for that domain and cannot count for %s, and nothing signs it with DKIM. "+
				"Give the sender a return address at %s, or have it sign with a DKIM key published for %s.",
			subject, seen.otherSPF.Domain, domain, domain, domain), true

	case !seen.otherDKIM.Domain.IsZero():
		return fmt.Sprintf(
			"%s is signed with a DKIM key for %s, which does not count for %s. Set the sender up to sign as %s, by publishing the DKIM record it provides under %s.",
			subject, seen.otherDKIM.Domain, domain, domain, domain), true

	case !seen.missedSPF.Domain.IsZero() && len(p.dkim) == 0:
		return fmt.Sprintf(
			"%s gets SPF %s for %s and carries no DKIM signature. Add the sending server to the SPF record for %s, or sign its mail with a DKIM key published for %s.",
			subject, strings.ToLower(seen.missedSPF.Result), domain, domain, domain), true
	}

	return "", false
}

// ifOurs is the first half of the action for a sender the program cannot
// vouch for: the fix, if it is ours. fallback finishes "if it is one of ours,
// ..." when the evidence names no specific fix. The caller says what follows
// if it is not ours, which depends on whether anything was blocked.
func ifOurs(ip netip.Addr, domain domainname.DomainName, e evidence, fallback string) string {
	fix, ok := remedy(domain, e)
	if !ok {
		return fmt.Sprintf("Check what %s is: if it is one of ours, %s", ip, fallback)
	}

	return fmt.Sprintf("If %s is one of ours: %s", ip, fix)
}
