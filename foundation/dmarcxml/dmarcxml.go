// Package dmarcxml is the wire format of a DMARC aggregate report: the XML
// schema from RFC 7489 Appendix C, and the container formats reporters wrap it
// in before attaching it to an email.
//
// Everything here is primitives on purpose. This is the outermost edge of the
// program — the shape of a document written by someone else's mail receiver,
// including its inconsistencies — and it must be free to be as sloppy as the
// documents are. Turning it into something trustworthy is the store layer's
// job: business/domain/report/stores/imapstore converts these structs into
// reportbus models and rejects what will not convert.
//
// Deliberately lenient where the wild is lenient: counts arrive as strings with
// whitespace, dates as either Unix seconds or ISO timestamps, and several large
// reporters omit elements the schema marks required. Being strict here would
// mean throwing away a whole report over one malformed record.
package dmarcxml

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Feedback is the root <feedback> element of an aggregate report.
type Feedback struct {
	XMLName         xml.Name `xml:"feedback"`
	Version         string   `xml:"version"`
	ReportMetadata  Metadata `xml:"report_metadata"`
	PolicyPublished Policy   `xml:"policy_published"`
	Records         []Record `xml:"record"`
}

// Metadata is <report_metadata>: who produced the report and for what window.
type Metadata struct {
	OrgName          string    `xml:"org_name"`
	Email            string    `xml:"email"`
	ExtraContactInfo string    `xml:"extra_contact_info"`
	ReportID         string    `xml:"report_id"`
	DateRange        DateRange `xml:"date_range"`
	Errors           []string  `xml:"error"`
}

// DateRange is <date_range>. The schema says Unix seconds; a minority of
// reporters send an ISO-8601 timestamp instead, so the values are kept as
// strings and interpreted by Begin and End.
type DateRange struct {
	Begin string `xml:"begin"`
	End   string `xml:"end"`
}

// Policy is <policy_published>: the DMARC record as the reporter read it,
// which is not necessarily the record published today.
type Policy struct {
	Domain         string `xml:"domain"`
	ADKIM          string `xml:"adkim"` // "r" (relaxed, default) or "s" (strict)
	ASPF           string `xml:"aspf"`  // "r" or "s"
	P              string `xml:"p"`
	SP             string `xml:"sp"`
	Pct            string `xml:"pct"`
	FailureOptions string `xml:"fo"`
}

// Record is one <record>: a group of messages sharing a source IP and an
// evaluation outcome.
type Record struct {
	Row         Row         `xml:"row"`
	Identifiers Identifiers `xml:"identifiers"`
	AuthResults AuthResults `xml:"auth_results"`
}

// Row is <row>: the source and the verdict.
type Row struct {
	SourceIP        string          `xml:"source_ip"`
	Count           string          `xml:"count"`
	PolicyEvaluated PolicyEvaluated `xml:"policy_evaluated"`
}

// PolicyEvaluated is <policy_evaluated>: what the receiver decided, after
// alignment.
type PolicyEvaluated struct {
	Disposition string   `xml:"disposition"`
	DKIM        string   `xml:"dkim"`
	SPF         string   `xml:"spf"`
	Reasons     []Reason `xml:"reason"`
}

// Reason is <reason>: why the receiver overrode the published policy — a
// local forwarding allowance, a mailing-list exception, sampling.
type Reason struct {
	Type    string `xml:"type"`
	Comment string `xml:"comment"`
}

// Identifiers is <identifiers>: the addresses the messages carried.
type Identifiers struct {
	EnvelopeTo   string `xml:"envelope_to"`
	EnvelopeFrom string `xml:"envelope_from"`
	HeaderFrom   string `xml:"header_from"`
}

// AuthResults is <auth_results>: the raw mechanism results, before alignment.
// A record may carry several DKIM signatures and, rarely, several SPF checks.
type AuthResults struct {
	DKIM []DKIMResult `xml:"dkim"`
	SPF  []SPFResult  `xml:"spf"`
}

// DKIMResult is one <dkim> element of <auth_results>.
type DKIMResult struct {
	Domain      string `xml:"domain"`
	Selector    string `xml:"selector"`
	Result      string `xml:"result"`
	HumanResult string `xml:"human_result"`
}

// SPFResult is one <spf> element of <auth_results>.
type SPFResult struct {
	Domain string `xml:"domain"`
	Scope  string `xml:"scope"`
	Result string `xml:"result"`
}

// Parse decodes one aggregate report from r.
//
// The decoder is given a CharsetReader that passes unknown encodings through
// unchanged: reports declare windows-1252 or iso-8859-1 now and then, and their
// content is invariably ASCII anyway. Failing the whole report over a charset
// declaration would lose data we can plainly read.
func Parse(r io.Reader) (Feedback, error) {
	dec := xml.NewDecoder(r)
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) {
		return input, nil
	}
	dec.Strict = false

	var fb Feedback
	if err := dec.Decode(&fb); err != nil {
		return Feedback{}, fmt.Errorf("decoding aggregate report: %w", err)
	}

	if fb.ReportMetadata.ReportID == "" && len(fb.Records) == 0 {
		return Feedback{}, fmt.Errorf("decoding aggregate report: no report id and no records — not an aggregate report")
	}

	return fb, nil
}

// BeginTime returns the start of the reporting window.
func (d DateRange) BeginTime() (time.Time, error) { return parseTimestamp(d.Begin) }

// EndTime returns the end of the reporting window.
func (d DateRange) EndTime() (time.Time, error) { return parseTimestamp(d.End) }

// MessageCount returns the number of messages this row represents. An absent or
// unparsable count is an error rather than a zero: a record that claims nothing
// would silently dilute every rate the triage layer computes.
func (r Row) MessageCount() (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(r.Count))
	if err != nil {
		return 0, fmt.Errorf("parsing record count %q: %w", r.Count, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("record count %d is negative", n)
	}

	return n, nil
}

// Percent returns the pct= sampling rate the policy was applied at, defaulting
// to 100 when absent or unparsable — which is what the DMARC default is, and
// what every reporter that omits the element means by omitting it.
func (p Policy) Percent() int {
	n, err := strconv.Atoi(strings.TrimSpace(p.Pct))
	if err != nil || n < 0 || n > 100 {
		return 100
	}

	return n
}

// StrictDKIM reports whether adkim=s was published; relaxed is the default.
func (p Policy) StrictDKIM() bool { return strings.EqualFold(strings.TrimSpace(p.ADKIM), "s") }

// StrictSPF reports whether aspf=s was published; relaxed is the default.
func (p Policy) StrictSPF() bool { return strings.EqualFold(strings.TrimSpace(p.ASPF), "s") }

// parseTimestamp accepts the Unix seconds the schema calls for, falling back to
// RFC 3339 for the reporters that send a timestamp instead.
func parseTimestamp(s string) (time.Time, error) {
	s = strings.TrimSpace(s)

	if secs, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(secs, 0).UTC(), nil
	}

	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing report timestamp %q: neither Unix seconds nor RFC 3339", s)
	}

	return t.UTC(), nil
}
