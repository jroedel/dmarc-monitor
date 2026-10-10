package dmarcxml_test

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"testing"

	"github.com/jroedel/dmarc-monitor/foundation/dmarcxml"
)

func fixture(t *testing.T) []byte {
	t.Helper()

	data, err := os.ReadFile("testdata/google-style.xml")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	return data
}

func TestParse(t *testing.T) {
	fb, err := dmarcxml.Parse(bytes.NewReader(fixture(t)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if got, want := fb.ReportMetadata.OrgName, "google.com"; got != want {
		t.Errorf("org name = %q, want %q", got, want)
	}
	if got, want := fb.PolicyPublished.Domain, "example.com"; got != want {
		t.Errorf("policy domain = %q, want %q", got, want)
	}
	if got, want := len(fb.Records), 3; got != want {
		t.Fatalf("records = %d, want %d", got, want)
	}

	begin, err := fb.ReportMetadata.DateRange.BeginTime()
	if err != nil {
		t.Fatalf("BeginTime: %v", err)
	}
	if got, want := begin.Unix(), int64(1755043200); got != want {
		t.Errorf("begin = %d, want %d", got, want)
	}

	count, err := fb.Records[0].Row.MessageCount()
	if err != nil {
		t.Fatalf("MessageCount: %v", err)
	}
	if want := 142; count != want {
		t.Errorf("first record count = %d, want %d", count, want)
	}

	if got, want := fb.Records[2].Row.PolicyEvaluated.Reasons[0].Type, "local_policy"; got != want {
		t.Errorf("override type = %q, want %q", got, want)
	}
}

// The pct= and adkim=/aspf= defaults matter: a report that omits them means the
// DMARC defaults, and reading an omission as zero would silently change what
// every rate computed from it means.
func TestPolicyDefaults(t *testing.T) {
	var p dmarcxml.Policy

	if got := p.Percent(); got != 100 {
		t.Errorf("absent pct = %d, want 100", got)
	}
	if p.StrictDKIM() || p.StrictSPF() {
		t.Error("absent adkim/aspf read as strict; the default is relaxed")
	}

	strict := dmarcxml.Policy{ADKIM: "s", ASPF: "S", Pct: "25"}
	if !strict.StrictDKIM() || !strict.StrictSPF() {
		t.Error("adkim=s / aspf=S not read as strict")
	}
	if got := strict.Percent(); got != 25 {
		t.Errorf("pct = %d, want 25", got)
	}
}

// Reporters send the same document raw, gzipped and zipped. Unpack must produce
// the identical report from all three, or a whole receiver's reports go missing
// depending on which container they chose.
func TestUnpackContainers(t *testing.T) {
	tests := containers(t, fixture(t))

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			reports, err := dmarcxml.Unpack(tt.filename, tt.data)
			if err != nil {
				t.Fatalf("Unpack: %v", err)
			}
			if len(reports) != 1 {
				t.Fatalf("got %d reports, want 1", len(reports))
			}
			if got, want := reports[0].ReportMetadata.ReportID, "18446744073709551615"; got != want {
				t.Errorf("report id = %q, want %q", got, want)
			}
		})
	}
}

// containers wraps one document in every container a reporter might choose.
func containers(t *testing.T, raw []byte) map[string]struct {
	filename string
	data     []byte
} {
	t.Helper()

	var gzipped bytes.Buffer
	zw := gzip.NewWriter(&gzipped)
	if _, err := zw.Write(raw); err != nil {
		t.Fatalf("gzipping: %v", err)
	}
	zw.Close()

	var zipped bytes.Buffer
	zipw := zip.NewWriter(&zipped)
	w, err := zipw.Create("report.xml")
	if err != nil {
		t.Fatalf("creating zip entry: %v", err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatalf("writing zip entry: %v", err)
	}
	zipw.Close()

	return map[string]struct {
		filename string
		data     []byte
	}{
		"raw xml":      {"report.xml", raw},
		"gzip":         {"report.xml.gz", gzipped.Bytes()},
		"zip":          {"report.zip", zipped.Bytes()},
		"mislabelled":  {"report.xml", gzipped.Bytes()},
		"no extension": {"report", zipped.Bytes()},
	}
}

// Extract is what an export hands a person to read, so it must be the
// reporter's document byte for byte, not this program's re-encoding of it.
func TestExtractKeepsTheReportersBytes(t *testing.T) {
	raw := fixture(t)

	for name, tt := range containers(t, raw) {
		t.Run(name, func(t *testing.T) {
			docs, err := dmarcxml.Extract(tt.filename, tt.data)
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			if len(docs) != 1 {
				t.Fatalf("got %d documents, want 1", len(docs))
			}
			if !bytes.Equal(docs[0].XML, raw) {
				t.Error("extracted XML differs from the document that was wrapped")
			}
		})
	}
}

func TestUnpackRejectsNonReports(t *testing.T) {
	tests := map[string][]byte{
		"empty":      {},
		"plain text": []byte("Hello, this is an out-of-office reply.\n"),
		"other xml":  []byte(`<?xml version="1.0"?><rss><channel/></rss>`),
	}

	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := dmarcxml.Unpack("thing.xml", data); err == nil {
				t.Error("want error, got none")
			}
		})
	}
}

func TestIsReportAttachment(t *testing.T) {
	tests := []struct {
		filename    string
		contentType string
		want        bool
	}{
		{"report.xml", "text/xml", true},
		{"report.xml.gz", "application/gzip", true},
		{"report.zip", "application/zip", true},
		{"unnamed", "application/x-zip-compressed", true},
		{"signature.asc", "application/pgp-signature", false},
		{"", "text/plain", false},
		{"logo.png", "image/png", false},
	}

	for _, tt := range tests {
		if got := dmarcxml.IsReportAttachment(tt.filename, tt.contentType); got != tt.want {
			t.Errorf("IsReportAttachment(%q, %q) = %v, want %v", tt.filename, tt.contentType, got, tt.want)
		}
	}
}
