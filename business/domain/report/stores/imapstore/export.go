package imapstore

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jroedel/dmarc-monitor/foundation/dmarcxml"
)

// ExportedReport is one aggregate report as it sits in the mailbox, for a
// person to read. It never enters the Business layer, so it is primitives
// throughout, and every string in it was written by a stranger's mail server.
type ExportedReport struct {
	UID        uint32
	ReceivedAt time.Time
	Org        string
	Domain     string
	ReportID   string
	Begin      time.Time
	End        time.Time

	// XML is the reporter's document byte for byte, out of its container.
	XML []byte
}

// Export hands emit every aggregate report in messages that arrived on or
// after since and before before. Only the dates count: IMAP searches the
// server's arrival date by day, in the server's timezone.
//
// It is read-only in the same way Fetch is, and more so: the mailbox is
// selected read-only, bodies are fetched with PEEK, and nothing is ever
// acknowledged. Messages already handled are included, since a report that
// has already raised an alert is usually exactly the one wanted.
//
// Problems with individual messages and attachments are collected and
// returned rather than stopping the export. An error from emit stops it.
func (s *Store) Export(ctx context.Context, since, before time.Time, emit func(ExportedReport) error) ([]error, error) {
	client, err := s.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if _, err := client.Select(s.cfg.Mailbox, &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
		return nil, fmt.Errorf("imapstore: selecting mailbox %q: %w", s.cfg.Mailbox, err)
	}

	criteria := imap.SearchCriteria{Since: since, Before: before}

	searched, err := client.UIDSearch(&criteria, nil).Wait()
	if err != nil {
		return nil, fmt.Errorf("imapstore: searching %q: %w", s.cfg.Mailbox, err)
	}

	uids := searched.AllUIDs()
	s.log.Info("imapstore: messages in the export window", "mailbox", s.cfg.Mailbox, "count", len(uids))

	options := imap.FetchOptions{
		UID:          true,
		InternalDate: true,
		BodySection:  []*imap.FetchItemBodySection{{Peek: true}},
	}

	var problems []error

	// One message at a time, for the reason fetchMessages gives.
	for _, uid := range uids {
		if err := ctx.Err(); err != nil {
			return problems, err
		}

		buffers, err := client.Fetch(imap.UIDSetNum(uid), &options).Collect()
		if err != nil {
			problems = append(problems, fmt.Errorf("imapstore: fetching uid %d: %w", uid, err))

			continue
		}

		for _, buf := range buffers {
			body := buf.FindBodySection(&imap.FetchItemBodySection{Peek: true})
			if body == nil {
				problems = append(problems, fmt.Errorf("imapstore: uid %d: server returned no body", buf.UID))

				continue
			}

			attachments, notes, err := reportAttachments(bytes.NewReader(body))
			problems = append(problems, notes...)
			if err != nil {
				problems = append(problems, fmt.Errorf("imapstore: uid %d: %w", buf.UID, err))

				continue
			}

			for _, att := range attachments {
				notes, err := exportAttachment(uint32(buf.UID), buf.InternalDate, att, emit)
				problems = append(problems, notes...)
				if err != nil {
					return problems, err
				}
			}
		}
	}

	if err := client.Logout().Wait(); err != nil {
		return problems, fmt.Errorf("imapstore: logging out: %w", err)
	}

	return problems, nil
}

// exportAttachment emits every report in one attachment. A document that does
// not parse is not a report and is noted, not emitted: the address is
// published, and a stranger's .zip is not a person's business to read.
func exportAttachment(uid uint32, received time.Time, att attachment, emit func(ExportedReport) error) ([]error, error) {
	docs, err := dmarcxml.Extract(att.filename, att.data)
	if err != nil {
		return []error{fmt.Errorf("imapstore: uid %d: %w", uid, err)}, nil
	}

	var problems []error

	for _, doc := range docs {
		fb, err := dmarcxml.Parse(bytes.NewReader(doc.XML))
		if err != nil {
			problems = append(problems, fmt.Errorf("imapstore: uid %d: %q is not an aggregate report: %w", uid, doc.Name, err))

			continue
		}

		// A date that will not parse costs the export its file name, not the
		// report: the zero time is still an answer, and the XML is intact.
		begin, _ := fb.ReportMetadata.DateRange.BeginTime()
		end, _ := fb.ReportMetadata.DateRange.EndTime()

		err = emit(ExportedReport{
			UID:        uid,
			ReceivedAt: received,
			Org:        fb.ReportMetadata.OrgName,
			Domain:     fb.PolicyPublished.Domain,
			ReportID:   fb.ReportMetadata.ReportID,
			Begin:      begin,
			End:        end,
			XML:        doc.XML,
		})
		if err != nil {
			return problems, err
		}
	}

	return problems, nil
}
