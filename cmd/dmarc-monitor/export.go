package main

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jroedel/dmarc-monitor/business/domain/report/stores/imapstore"
)

// -export-reports exists for the moment an alert arrives and the question is
// what the receiver actually saw. The alert is a summary; the answer is in the
// <auth_results> of the report it summarised, which on the server is reachable
// only as this binary, with these credentials. So the binary hands them over:
// read-only, as a tar on stdout, which deploy/deploy.sh unpacks on a person's
// own machine. Nothing is written on the server.

// exportDateLayout is what -since and -until take.
const exportDateLayout = "2006-01-02"

// exportMargin widens the window past -until. A receiver sends the report for
// a day after that day ends, so the report covering -until arrives the day
// after it; without the margin, the last day asked for would be missing.
const exportMargin = 24 * time.Hour

// reportExporter is the one thing the export needs from the mailbox.
type reportExporter interface {
	Export(ctx context.Context, since, before time.Time, emit func(imapstore.ExportedReport) error) ([]error, error)
}

// exportWindow turns -since and -until into the arrival dates to search:
// on or after since, and before the day after until, plus the margin. -until
// defaults to today, in UTC like every date in a report.
func exportWindow(since, until string, now time.Time) (time.Time, time.Time, error) {
	if since == "" {
		return time.Time{}, time.Time{}, errors.New("-export-reports needs -since YYYY-MM-DD: the first day whose reports are wanted")
	}

	from, err := time.Parse(exportDateLayout, since)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("-since %q is not a date like 2026-10-04", since)
	}

	last := now.UTC().Truncate(24 * time.Hour)
	if until != "" {
		last, err = time.Parse(exportDateLayout, until)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("-until %q is not a date like 2026-10-09", until)
		}
	}

	if last.Before(from) {
		return time.Time{}, time.Time{}, fmt.Errorf("-until %s is before -since %s", last.Format(exportDateLayout), since)
	}

	return from, last.Add(24*time.Hour + exportMargin), nil
}

// exportReports writes every report in the window to w as a tar archive.
func exportReports(ctx context.Context, log *slog.Logger, store reportExporter, from, before time.Time, w io.Writer) error {
	tw := tar.NewWriter(w)
	names := make(map[string]bool)
	written := 0

	problems, err := store.Export(ctx, from, before, func(r imapstore.ExportedReport) error {
		name := uniqueName(names, exportFileName(r))

		header := tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Mode:     0o600,
			Size:     int64(len(r.XML)),
			ModTime:  r.ReceivedAt,
		}

		if err := tw.WriteHeader(&header); err != nil {
			return fmt.Errorf("writing %s to the archive: %w", name, err)
		}
		if _, err := tw.Write(r.XML); err != nil {
			return fmt.Errorf("writing %s to the archive: %w", name, err)
		}

		written++

		return nil
	})

	for _, p := range problems {
		log.Warn("skipped while exporting", "err", p)
	}

	if err != nil {
		return err
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("finishing the archive: %w", err)
	}

	log.Info("exported reports",
		"reports", written,
		"received from", from.Format(exportDateLayout),
		"received before", before.Format(exportDateLayout))

	return nil
}

// exportFileName names a report by the day it covers, who sent it, the domain
// and the reporter's id, so that a directory listing sorts by date and a
// report can be found by the alert that mentions it.
//
// Every part comes from the report, which is to say from anyone on the
// internet: the name is built from a short allowlist of characters, so no
// report can name a path outside the directory it is unpacked into.
func exportFileName(r imapstore.ExportedReport) string {
	day := "unknown-date"
	if !r.Begin.IsZero() {
		day = r.Begin.UTC().Format(exportDateLayout)
	}

	return strings.Join([]string{day, safeName(r.Org), safeName(r.Domain), safeName(r.ReportID)}, "_") + ".xml"
}

// safeName keeps letters, digits, dots and hyphens, turns runs of anything
// else into one hyphen, and caps the length. It never returns a name that is
// empty or starts with a dot.
func safeName(s string) string {
	const maxLen = 64

	var b strings.Builder
	dash := false

	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
			dash = false
		case !dash:
			b.WriteByte('-')
			dash = true
		}

		if b.Len() >= maxLen {
			break
		}
	}

	name := strings.Trim(b.String(), ".-")
	if name == "" {
		return "unknown"
	}

	return name
}

// uniqueName suffixes a repeated name. A receiver that resends a report sends
// the same id twice, and both copies are worth having over one overwriting
// the other in silence.
func uniqueName(seen map[string]bool, name string) string {
	candidate := name
	for n := 2; seen[candidate]; n++ {
		candidate = strings.TrimSuffix(name, ".xml") + "-" + strconv.Itoa(n) + ".xml"
	}

	seen[candidate] = true

	return candidate
}

// refuseTerminal stops a tar from being printed into a person's terminal.
func refuseTerminal(f *os.File) error {
	info, err := f.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return nil
	}

	return errors.New("-export-reports writes a tar archive to stdout; pipe it into tar, as in: dmarc-monitor -export-reports -since 2026-10-04 | tar -x -C reports")
}
