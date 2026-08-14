package reportbus

import (
	"net/netip"
	"time"

	"github.com/jroedel/dmarc-monitor/business/types/authresult"
	"github.com/jroedel/dmarc-monitor/business/types/disposition"
	"github.com/jroedel/dmarc-monitor/business/types/domainname"
	"github.com/jroedel/dmarc-monitor/business/types/email"
)

// Report is one DMARC aggregate report: a receiver's account of every message
// it saw claiming to be from a domain during a window, grouped by source.
//
// The XML this came from is in foundation/dmarcxml and stays there. What
// reaches here has been parsed into strong types and is trusted: a Report in
// hand is one that can be reasoned about without re-checking whether its
// domains are domains.
type Report struct {
	// Ref is the source's opaque handle for the message this report arrived in
	// — an IMAP UID, a filename. It is a primitive because its meaning belongs
	// entirely to the store that issued it; the Business layer only carries it
	// back so the store can acknowledge the right message.
	Ref string

	ID         string
	Org        string
	OrgEmail   email.Email
	Domain     domainname.DomainName
	Begin      time.Time
	End        time.Time
	Received   time.Time
	Policy     Policy
	Records    []Record
	ParseNotes []string
}

// Policy is the DMARC record as the reporting receiver read it during the
// window. It is not necessarily what is published now, which is exactly why it
// is worth keeping: a report showing p=none for a domain that was moved to
// p=reject last week is a report from before the change.
type Policy struct {
	Domain     domainname.DomainName
	Requested  disposition.Disposition
	Subdomain  disposition.Disposition
	Percent    int
	StrictDKIM bool
	StrictSPF  bool
}

// Record is one row of the report: all messages from one source IP that were
// evaluated the same way.
type Record struct {
	SourceIP    netip.Addr
	Count       int
	Disposition disposition.Disposition
	DKIM        authresult.AuthResult
	SPF         authresult.AuthResult
	HeaderFrom  domainname.DomainName
	EnvelopeTo  string
	Overrides   []Override
	DKIMAuth    []DKIMAuth
	SPFAuth     []SPFAuth
}

// Override is a receiver's stated reason for not applying the published policy
// — a local forwarding allowance, a mailing list, sampling. It is the single
// most useful field for suppressing false alarms: mail that "failed" because a
// receiver knowingly forwarded it is not a misconfiguration.
type Override struct {
	Type    string
	Comment string
}

// DKIMAuth is a raw DKIM signature result, before alignment was considered.
type DKIMAuth struct {
	Domain   domainname.DomainName
	Selector string
	Result   string
}

// SPFAuth is a raw SPF result, before alignment was considered.
type SPFAuth struct {
	Domain domainname.DomainName
	Scope  string
	Result string
}

// Volume is the total number of messages the report accounts for.
func (r Report) Volume() int {
	var total int
	for _, rec := range r.Records {
		total += rec.Count
	}

	return total
}

// PassingVolume is the number of messages that passed DMARC — at least one
// aligned mechanism, which is what the standard requires.
func (r Report) PassingVolume() int {
	var total int
	for _, rec := range r.Records {
		if rec.Passed() {
			total += rec.Count
		}
	}

	return total
}

// FailingVolume is the number of messages that passed neither mechanism.
func (r Report) FailingVolume() int { return r.Volume() - r.PassingVolume() }

// Passed reports whether the record satisfied DMARC. One aligned mechanism is
// enough; the other failing is normal and not on its own interesting.
func (rec Record) Passed() bool { return rec.DKIM.Passed() || rec.SPF.Passed() }

// Overridden reports whether the receiver gave a reason for departing from the
// published policy.
func (rec Record) Overridden() bool { return len(rec.Overrides) > 0 }

// Aligned reports whether the header-from domain aligns with the policy domain
// under the report's published alignment mode. A record whose header-from is a
// different domain entirely is someone else's mail being reported to us —
// forwarders and mailing lists do this constantly.
func (rec Record) Aligned(p Policy) bool {
	return rec.HeaderFrom.Aligns(p.Domain, p.StrictDKIM || p.StrictSPF)
}
