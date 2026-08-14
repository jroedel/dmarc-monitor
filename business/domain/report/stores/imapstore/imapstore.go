// Package imapstore reads DMARC aggregate reports out of an IMAP mailbox.
//
// This is the Storage layer for the report domain: it speaks to the outside
// world, deals in that world's primitives — UIDs, MIME parts, XML — and hands
// the Business layer nothing but validated models. Everything sloppy about
// real DMARC mail is absorbed here.
//
// The design rule that matters is that fetching is read-only and
// acknowledgement is a separate call. A run that crashes after fetching but
// before alerting leaves the mailbox exactly as it found it, and the next run
// does the work again. The alternative — flagging messages as they are read —
// turns any crash into permanently lost reports, which is the one failure this
// program cannot detect or recover from.
package imapstore

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/jroedel/dmarc-monitor/business/domain/report/reportbus"
	"github.com/jroedel/dmarc-monitor/foundation/dmarcxml"
)

// Config is everything the store needs to reach and read a mailbox.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	Mailbox  string

	// STARTTLS opens in the clear and upgrades. When false the connection is
	// TLS from the first byte. There is no third option: this store never
	// speaks plaintext to a server, because it is about to send a password.
	STARTTLS bool

	// MarkSeen flags acknowledged messages \Seen. MoveTo, if set, moves them to
	// that mailbox instead — the folder must already exist, since creating one
	// on someone's mail account is not this program's business.
	MarkSeen bool
	MoveTo   string

	// IncludeSeen widens the search from unread messages to every message in the
	// mailbox. Off by default, because \Seen is what makes the mailbox its own
	// queue and a human who opened a report by hand is looking at it.
	//
	// It exists for two real cases: a first run against a mailbox that already
	// holds months of reports, and a test mailbox whose messages have been read
	// in a webmail client. Nothing is re-alerted either way — the checkpoint
	// deduplicates on the reporter's own report id — but it is opt-in because
	// the first run of it can process a great many messages.
	IncludeSeen bool

	// DryRun makes Ack a no-op. The mailbox is left untouched so a run can be
	// rehearsed as many times as needed.
	DryRun bool

	// Timeout bounds the whole conversation with the server.
	Timeout time.Duration
}

// Store is an IMAP-backed report source.
type Store struct {
	cfg Config
	log *slog.Logger
}

// defaultTimeout is generous: a mailbox with a month of unread reports takes
// real time to download, and a slow server is not a reason to lose a run.
const defaultTimeout = 5 * time.Minute

// NewStore constructs an IMAP report source. It does not connect; each Fetch
// and Ack opens and closes its own connection, which is the right trade for a
// program that runs for a second every six hours.
func NewStore(log *slog.Logger, cfg Config) *Store {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Mailbox == "" {
		cfg.Mailbox = "INBOX"
	}

	return &Store{cfg: cfg, log: log}
}

// Fetch returns every message in the mailbox that carries at least one parsable
// aggregate report and has not been handled yet.
//
// Unread is the default selection criterion, and it is what makes the mailbox
// itself the queue: a message this program has finished with is \Seen, and a
// message a human has opened by hand is deliberately skipped, because they are
// looking at it. Config.IncludeSeen widens it to everything, for a first run
// over an archive that has already been read.
func (s *Store) Fetch(ctx context.Context) ([]reportbus.Report, []error, error) {
	client, err := s.connect(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer client.Close()

	if _, err := client.Select(s.cfg.Mailbox, &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
		return nil, nil, fmt.Errorf("imapstore: selecting mailbox %q: %w", s.cfg.Mailbox, err)
	}

	// The zero criteria matches every message; NotFlag \Seen is the usual
	// narrowing to what has not been handled yet.
	var criteria imap.SearchCriteria
	if !s.cfg.IncludeSeen {
		criteria.NotFlag = []imap.Flag{imap.FlagSeen}
	}

	searched, err := client.UIDSearch(&criteria, nil).Wait()
	if err != nil {
		return nil, nil, fmt.Errorf("imapstore: searching %q: %w", s.cfg.Mailbox, err)
	}

	uids := searched.AllUIDs()
	if len(uids) == 0 {
		return nil, nil, nil
	}

	s.log.Debug("imapstore: messages to examine", "mailbox", s.cfg.Mailbox, "count", len(uids), "including read", s.cfg.IncludeSeen)

	return s.fetchMessages(ctx, client, uids)
}

// fetchMessages downloads the messages one at a time.
//
// One at a time on purpose: a single FETCH of a hundred whole messages buffers
// all of them, and the point of the cap in mime.go is defeated if the client
// has already held everything in memory to get there.
func (s *Store) fetchMessages(ctx context.Context, client *imapclient.Client, uids []imap.UID) ([]reportbus.Report, []error, error) {
	options := imap.FetchOptions{
		UID:          true,
		InternalDate: true,
		Envelope:     true,
		BodySection:  []*imap.FetchItemBodySection{{Peek: true}},
	}

	var (
		reports  []reportbus.Report
		problems []error
	)

	for _, uid := range uids {
		if err := ctx.Err(); err != nil {
			return reports, problems, err
		}

		buffers, err := client.Fetch(imap.UIDSetNum(uid), &options).Collect()
		if err != nil {
			problems = append(problems, fmt.Errorf("imapstore: fetching uid %d: %w", uid, err))

			continue
		}

		for _, buf := range buffers {
			found, notes := s.reportsFrom(buf)
			reports = append(reports, found...)
			problems = append(problems, notes...)
		}
	}

	return reports, problems, nil
}

// reportsFrom turns one fetched message into whatever reports it carries.
//
// A message with no report attachment is not a problem and produces nothing:
// the address that receives DMARC reports also receives spam, autoreplies and
// the occasional human being.
func (s *Store) reportsFrom(buf *imapclient.FetchMessageBuffer) ([]reportbus.Report, []error) {
	ref := strconv.FormatUint(uint64(buf.UID), 10)

	body := buf.FindBodySection(&imap.FetchItemBodySection{Peek: true})
	if body == nil {
		return nil, []error{fmt.Errorf("imapstore: uid %s: server returned no body", ref)}
	}

	attachments, problems, err := reportAttachments(bytes.NewReader(body))
	if err != nil {
		return nil, []error{fmt.Errorf("imapstore: uid %s: %w", ref, err)}
	}

	received := buf.InternalDate
	if received.IsZero() && buf.Envelope != nil {
		received = buf.Envelope.Date
	}

	var reports []reportbus.Report
	for _, att := range attachments {
		feedbacks, err := dmarcxml.Unpack(att.filename, att.data)
		if err != nil {
			// Not necessarily an error worth showing an operator: a .zip that
			// is not a report is just other mail. Recorded at the same level as
			// everything else and left for the caller to log.
			problems = append(problems, fmt.Errorf("imapstore: uid %s: %w", ref, err))

			continue
		}

		for _, fb := range feedbacks {
			report, err := toBusReport(ref, received, fb)
			if err != nil {
				problems = append(problems, fmt.Errorf("imapstore: uid %s: %w", ref, err))

				continue
			}

			reports = append(reports, report)
		}
	}

	return reports, problems
}

// Ack marks the messages behind the given refs as handled, by flag or by move.
//
// Refs that are not UIDs are skipped rather than failing the batch: a
// hand-constructed report in a test has no business stopping the real ones from
// being acknowledged.
func (s *Store) Ack(ctx context.Context, refs []string) error {
	if len(refs) == 0 {
		return nil
	}

	if s.cfg.DryRun {
		s.log.Info("imapstore: dry run, leaving messages unread", "count", len(refs))

		return nil
	}

	var uids imap.UIDSet
	for _, ref := range refs {
		n, err := strconv.ParseUint(ref, 10, 32)
		if err != nil {
			s.log.Warn("imapstore: skipping unacknowledgeable ref", "ref", ref)

			continue
		}

		uids.AddNum(imap.UID(n))
	}

	if len(uids) == 0 {
		return nil
	}

	client, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	if _, err := client.Select(s.cfg.Mailbox, nil).Wait(); err != nil {
		return fmt.Errorf("imapstore: selecting mailbox %q: %w", s.cfg.Mailbox, err)
	}

	// Flag before moving. If the move fails the message is at least marked
	// handled and will not be reprocessed; if the flag were set after a
	// successful move it would be racing a message that no longer exists here.
	if s.cfg.MarkSeen || s.cfg.MoveTo != "" {
		store := imap.StoreFlags{
			Op:     imap.StoreFlagsAdd,
			Silent: true,
			Flags:  []imap.Flag{imap.FlagSeen},
		}

		if err := client.Store(uids, &store, nil).Close(); err != nil {
			return fmt.Errorf("imapstore: flagging %s as seen: %w", uids, err)
		}
	}

	if s.cfg.MoveTo != "" {
		if _, err := client.Move(uids, s.cfg.MoveTo).Wait(); err != nil {
			return fmt.Errorf("imapstore: moving %s to %q: %w", uids, s.cfg.MoveTo, err)
		}
	}

	if err := client.Logout().Wait(); err != nil {
		return fmt.Errorf("imapstore: logging out: %w", err)
	}

	return nil
}

// Check verifies that the configured mailbox can be reached, authenticated to
// and selected. It exists so an operator can prove the credentials work without
// running a cycle that might send mail.
func (s *Store) Check(ctx context.Context) error {
	client, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	data, err := client.Select(s.cfg.Mailbox, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return fmt.Errorf("imapstore: selecting mailbox %q: %w", s.cfg.Mailbox, err)
	}

	s.log.Info("imapstore: mailbox reachable",
		"host", s.cfg.Host,
		"mailbox", s.cfg.Mailbox,
		"messages", data.NumMessages)

	return client.Logout().Wait()
}

// connect dials, upgrades if asked, and logs in.
//
// TLS is not optional in either mode, and the server name is always verified:
// an IMAP login sends the password in the clear inside the session, so a
// downgrade here is a password disclosure, not an inconvenience.
func (s *Store) connect(ctx context.Context) (*imapclient.Client, error) {
	address := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	tlsConfig := tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}

	options := imapclient.Options{
		TLSConfig: &tlsConfig,
	}

	dialer := net.Dialer{Timeout: s.cfg.Timeout}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("imapstore: dialling %s: %w", address, err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(s.cfg.Timeout))
	}

	var client *imapclient.Client
	switch {
	case s.cfg.STARTTLS:
		client, err = imapclient.NewStartTLS(conn, &options)
		if err != nil {
			conn.Close()

			return nil, fmt.Errorf("imapstore: starting TLS with %s: %w", address, err)
		}

	default:
		client = imapclient.New(tls.Client(conn, &tlsConfig), &options)
		if err := client.WaitGreeting(); err != nil {
			client.Close()

			return nil, fmt.Errorf("imapstore: TLS handshake with %s: %w", address, err)
		}
	}

	if err := client.Login(s.cfg.Username, s.cfg.Password).Wait(); err != nil {
		client.Close()

		return nil, fmt.Errorf("imapstore: logging in to %s as %q: %w", address, s.cfg.Username, wrapAuthError(err))
	}

	return client, nil
}

// wrapAuthError keeps the server's own words but strips any chance of the
// password appearing in a log line, which some servers echo back on failure.
func wrapAuthError(err error) error {
	var status *imap.Error
	if errors.As(err, &status) {
		return fmt.Errorf("server said %q", status.Text)
	}

	return err
}
