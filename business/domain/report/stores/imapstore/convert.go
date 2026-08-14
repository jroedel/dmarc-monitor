package imapstore

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jroedel/dmarc-monitor/business/domain/report/reportbus"
	"github.com/jroedel/dmarc-monitor/business/types/authresult"
	"github.com/jroedel/dmarc-monitor/business/types/disposition"
	"github.com/jroedel/dmarc-monitor/business/types/domainname"
	"github.com/jroedel/dmarc-monitor/business/types/email"
	"github.com/jroedel/dmarc-monitor/foundation/dmarcxml"
)

// toBusReport converts a decoded XML report into the Business model. This is
// the boundary the rest of the program is built on: everything upstream of it
// is a string somebody else wrote, everything downstream is a validated type.
//
// It fails only on what makes the report meaningless — no policy domain, no
// usable window. Individual bad records are dropped and noted instead, because
// a report is an aggregate: losing one row of a thousand costs a rounding
// error, losing the report costs the whole day's visibility for that domain.
func toBusReport(ref string, received time.Time, fb dmarcxml.Feedback) (reportbus.Report, error) {
	policy, err := toBusPolicy(fb.PolicyPublished)
	if err != nil {
		return reportbus.Report{}, fmt.Errorf("policy_published: %w", err)
	}

	begin, err := fb.ReportMetadata.DateRange.BeginTime()
	if err != nil {
		return reportbus.Report{}, fmt.Errorf("report %q: %w", fb.ReportMetadata.ReportID, err)
	}

	end, err := fb.ReportMetadata.DateRange.EndTime()
	if err != nil {
		return reportbus.Report{}, fmt.Errorf("report %q: %w", fb.ReportMetadata.ReportID, err)
	}

	report := reportbus.Report{
		Ref:      ref,
		ID:       strings.TrimSpace(fb.ReportMetadata.ReportID),
		Org:      strings.TrimSpace(fb.ReportMetadata.OrgName),
		Domain:   policy.Domain,
		Begin:    begin,
		End:      end,
		Received: received,
		Policy:   policy,
	}

	// A reporter's own contact address failing to parse says nothing about the
	// data it sent, so it is recorded and moved past.
	if raw := strings.TrimSpace(fb.ReportMetadata.Email); raw != "" {
		addr, err := email.Parse(raw)
		if err != nil {
			report.ParseNotes = append(report.ParseNotes, fmt.Sprintf("reporter address %q: %v", raw, err))
		} else {
			report.OrgEmail = addr
		}
	}

	for _, e := range fb.ReportMetadata.Errors {
		if e = strings.TrimSpace(e); e != "" {
			report.ParseNotes = append(report.ParseNotes, "reporter noted: "+e)
		}
	}

	for i, rec := range fb.Records {
		busRec, err := toBusRecord(rec)
		if err != nil {
			report.ParseNotes = append(report.ParseNotes, fmt.Sprintf("record %d dropped: %v", i, err))

			continue
		}

		report.Records = append(report.Records, busRec)
	}

	if len(report.Records) == 0 {
		return reportbus.Report{}, fmt.Errorf("report %q from %q: no usable records", report.ID, report.Org)
	}

	return report, nil
}

func toBusPolicy(p dmarcxml.Policy) (reportbus.Policy, error) {
	domain, err := domainname.Parse(p.Domain)
	if err != nil {
		return reportbus.Policy{}, fmt.Errorf("domain: %w", err)
	}

	// An absent or unrecognised p= means the receiver told us nothing about
	// what it was asked to do, which for our purposes is the same as p=none:
	// nothing was being discarded on the domain's instruction.
	requested := parseDispositionOr(p.P, disposition.None)

	return reportbus.Policy{
		Domain:     domain,
		Requested:  requested,
		Subdomain:  parseDispositionOr(p.SP, requested),
		Percent:    p.Percent(),
		StrictDKIM: p.StrictDKIM(),
		StrictSPF:  p.StrictSPF(),
	}, nil
}

func toBusRecord(rec dmarcxml.Record) (reportbus.Record, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(rec.Row.SourceIP))
	if err != nil {
		return reportbus.Record{}, fmt.Errorf("source_ip %q: not an IP address", rec.Row.SourceIP)
	}

	count, err := rec.Row.MessageCount()
	if err != nil {
		return reportbus.Record{}, err
	}

	// A row with no messages carries no information and would only add noise to
	// every rate computed from it.
	if count == 0 {
		return reportbus.Record{}, fmt.Errorf("source %s: zero messages", ip)
	}

	headerFrom, err := domainname.Parse(rec.Identifiers.HeaderFrom)
	if err != nil {
		return reportbus.Record{}, fmt.Errorf("header_from %q: %w", rec.Identifiers.HeaderFrom, err)
	}

	busRec := reportbus.Record{
		SourceIP:   ip.Unmap(),
		Count:      count,
		HeaderFrom: headerFrom,
		EnvelopeTo: strings.TrimSpace(rec.Identifiers.EnvelopeTo),

		// An absent disposition means the receiver delivered normally, and an
		// absent dkim/spf result means that mechanism did not produce an
		// aligned pass. Both defaults are the reading that cannot invent an
		// alert out of missing data.
		Disposition: parseDispositionOr(rec.Row.PolicyEvaluated.Disposition, disposition.None),
		DKIM:        parseAuthResultOr(rec.Row.PolicyEvaluated.DKIM, authresult.Fail),
		SPF:         parseAuthResultOr(rec.Row.PolicyEvaluated.SPF, authresult.Fail),
	}

	for _, reason := range rec.Row.PolicyEvaluated.Reasons {
		busRec.Overrides = append(busRec.Overrides, reportbus.Override{
			Type:    strings.TrimSpace(reason.Type),
			Comment: strings.TrimSpace(reason.Comment),
		})
	}

	for _, d := range rec.AuthResults.DKIM {
		domain, err := domainname.Parse(d.Domain)
		if err != nil {
			continue
		}

		busRec.DKIMAuth = append(busRec.DKIMAuth, reportbus.DKIMAuth{
			Domain:   domain,
			Selector: strings.TrimSpace(d.Selector),
			Result:   strings.ToLower(strings.TrimSpace(d.Result)),
		})
	}

	for _, s := range rec.AuthResults.SPF {
		domain, err := domainname.Parse(s.Domain)
		if err != nil {
			continue
		}

		busRec.SPFAuth = append(busRec.SPFAuth, reportbus.SPFAuth{
			Domain: domain,
			Scope:  strings.ToLower(strings.TrimSpace(s.Scope)),
			Result: strings.ToLower(strings.TrimSpace(s.Result)),
		})
	}

	return busRec, nil
}

func parseDispositionOr(raw string, def disposition.Disposition) disposition.Disposition {
	d, err := disposition.Parse(strings.ToLower(strings.TrimSpace(raw)))
	if err != nil {
		return def
	}

	return d
}

func parseAuthResultOr(raw string, def authresult.AuthResult) authresult.AuthResult {
	r, err := authresult.Parse(strings.ToLower(strings.TrimSpace(raw)))
	if err != nil {
		return def
	}

	return r
}
