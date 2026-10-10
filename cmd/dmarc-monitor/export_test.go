package main

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jroedel/dmarc-monitor/business/domain/report/stores/imapstore"
)

// The window is what decides whether the report a person is looking for is in
// the archive at all. The report for a day arrives after that day, so the
// search must reach past -until.
func TestExportWindow(t *testing.T) {
	now := time.Date(2026, 10, 10, 15, 30, 0, 0, time.UTC)

	tests := map[string]struct {
		since, until string
		from, before string
		wantErr      bool
	}{
		"one day":            {since: "2026-10-04", until: "2026-10-04", from: "2026-10-04", before: "2026-10-06"},
		"a span":             {since: "2026-10-04", until: "2026-10-08", from: "2026-10-04", before: "2026-10-10"},
		"until defaults":     {since: "2026-10-08", from: "2026-10-08", before: "2026-10-12"},
		"no since":           {until: "2026-10-08", wantErr: true},
		"since not a date":   {since: "last week", wantErr: true},
		"until not a date":   {since: "2026-10-04", until: "10/08/2026", wantErr: true},
		"until before since": {since: "2026-10-08", until: "2026-10-04", wantErr: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			from, before, err := exportWindow(tt.since, tt.until, now)

			switch {
			case tt.wantErr && err == nil:
				t.Fatalf("want an error, got window %s to %s", from, before)
			case tt.wantErr:
				return
			case err != nil:
				t.Fatalf("exportWindow: %v", err)
			}

			if got := from.Format(exportDateLayout); got != tt.from {
				t.Errorf("from = %s, want %s", got, tt.from)
			}
			if got := before.Format(exportDateLayout); got != tt.before {
				t.Errorf("before = %s, want %s", got, tt.before)
			}
		})
	}
}

// Every part of the name is chosen by whoever sent the report, and the
// mailbox is a published address. Nothing they write may climb out of the
// directory the archive is unpacked into, or hide the file from ls.
func TestExportFileNameIsSafe(t *testing.T) {
	begin := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

	tests := map[string]struct {
		report imapstore.ExportedReport
		want   string
	}{
		"google": {
			report: imapstore.ExportedReport{Org: "google.com", Domain: "schoenstatt.link", ReportID: "4719233046591234567", Begin: begin},
			want:   "2026-10-04_google.com_schoenstatt.link_4719233046591234567.xml",
		},
		"traversal": {
			report: imapstore.ExportedReport{Org: "../../etc", Domain: "/root/.ssh", ReportID: "..", Begin: begin},
			want:   "2026-10-04_etc_root-.ssh_unknown.xml",
		},
		"spaces and punctuation": {
			report: imapstore.ExportedReport{Org: "Mail.Ru  Group", Domain: "example.org", ReportID: "<abc@def>", Begin: begin},
			want:   "2026-10-04_Mail.Ru-Group_example.org_abc-def.xml",
		},
		"no date": {
			report: imapstore.ExportedReport{Org: "x", Domain: "y", ReportID: "z"},
			want:   "unknown-date_x_y_z.xml",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := exportFileName(tt.report)
			if got != tt.want {
				t.Errorf("name = %q, want %q", got, tt.want)
			}
			if strings.ContainsAny(got, `/\`) || strings.HasPrefix(got, ".") {
				t.Errorf("name %q could escape or hide in the target directory", got)
			}
		})
	}

	long := safeName(strings.Repeat("a", 500))
	if len(long) > 64 {
		t.Errorf("safeName kept %d bytes, want at most 64", len(long))
	}
}

type fakeExporter struct {
	reports  []imapstore.ExportedReport
	problems []error
	err      error
}

func (f fakeExporter) Export(_ context.Context, _, _ time.Time, emit func(imapstore.ExportedReport) error) ([]error, error) {
	for _, r := range f.reports {
		if err := emit(r); err != nil {
			return f.problems, err
		}
	}

	return f.problems, f.err
}

// The archive is the whole product of an export: the reporter's bytes, under
// names that do not collide, with a resent report kept rather than lost.
func TestExportReportsWritesATar(t *testing.T) {
	begin := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	report := imapstore.ExportedReport{Org: "google.com", Domain: "schoenstatt.link", ReportID: "42", Begin: begin, XML: []byte("<feedback/>")}
	resent := report
	resent.XML = []byte("<feedback>again</feedback>")

	store := fakeExporter{
		reports:  []imapstore.ExportedReport{report, resent},
		problems: []error{errors.New("uid 7: not a report")},
	}

	var out bytes.Buffer
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := exportReports(t.Context(), log, store, begin, begin.AddDate(0, 0, 2), &out); err != nil {
		t.Fatalf("exportReports: %v", err)
	}

	got := make(map[string]string)
	tr := tar.NewReader(&out)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading the archive: %v", err)
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("reading %s: %v", h.Name, err)
		}
		got[h.Name] = string(data)
	}

	want := map[string]string{
		"2026-10-08_google.com_schoenstatt.link_42.xml":   "<feedback/>",
		"2026-10-08_google.com_schoenstatt.link_42-2.xml": "<feedback>again</feedback>",
	}

	if len(got) != len(want) {
		t.Fatalf("archive holds %v, want %v", got, want)
	}
	for name, body := range want {
		if got[name] != body {
			t.Errorf("%s = %q, want %q", name, got[name], body)
		}
	}
}

// A mailbox that fails partway must fail the export, not end it with a
// truncated archive that looks complete.
func TestExportReportsFailsOnAMailboxError(t *testing.T) {
	store := fakeExporter{err: errors.New("connection reset")}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	var out bytes.Buffer
	if err := exportReports(t.Context(), log, store, time.Now(), time.Now(), &out); err == nil {
		t.Fatal("want the mailbox error, got none")
	}
}
