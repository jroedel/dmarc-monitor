// Package smtpstore delivers alerts through an SMTP submission service.
//
// This is the Storage layer for the alert domain, and the only place in the
// program that can affect anyone outside it. Three rules follow from that.
//
// Talking to a relay over a network means TLS, with the certificate verified.
// A submission session sends a password and then sends mail as the domain; a
// silent downgrade to plaintext would leak the first and let anyone forge the
// second. A server that will not do STARTTLS is refused, not tolerated.
//
// The exception is a relay on the loopback address, where plaintext is allowed
// and a certificate is not verified. That is not a relaxation of the rule but
// the same rule applied honestly: nothing is on the wire to intercept. It earns
// its keep because a message handed to the local mail server goes out as the
// host's own mail — its SPF standing, its DKIM signature — while the same
// message pushed through a remote relay has neither, and is exactly the mail a
// tightened DMARC policy would then quarantine.
//
// And the relay is deliberately not the IMAP account. The address that collects
// DMARC reports is usually a role mailbox with no send rights, and the alert
// has to go out precisely when the domain's mail flow is in question — so it
// gets its own credentials, its own host, and its own failure.
package smtpstore

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strconv"
	"time"

	"github.com/jroedel/dmarc-monitor/business/domain/alert/alertbus"
)

// Config is everything needed to hand a message to a relay.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string

	// Security is "tls" (implicit, port 465), "starttls" (port 587) or "none".
	//
	// A primitive rather than a type from the config package: this is the
	// storage layer, and what reaches it is a string the config layer has
	// already validated.
	//
	// "none" is plaintext and belongs to exactly one arrangement — the mail
	// server on this same machine. Handing the message to it means the alert
	// leaves the host the way the host's own mail does, with its SPF standing
	// and its DKIM signature, instead of arriving from a relay that has
	// neither. The connection never touches a network. Config refuses this
	// mode for any host that is not loopback, and so does this package.
	Security string

	// Timeout bounds the whole submission.
	Timeout time.Duration
}

// Store is an SMTP-backed alert sender.
type Store struct {
	cfg Config
	log *slog.Logger
}

const defaultTimeout = 60 * time.Second

// NewStore constructs the sender. It does not connect.
func NewStore(log *slog.Logger, cfg Config) *Store {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}

	return &Store{cfg: cfg, log: log}
}

// Send submits one message.
func (s *Store) Send(ctx context.Context, msg alertbus.Message) error {
	wire, err := toSMTPMessage(msg)
	if err != nil {
		return err
	}

	client, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.Mail(msg.From.String()); err != nil {
		return fmt.Errorf("smtpstore: MAIL FROM %s: %w", msg.From, err)
	}

	for _, to := range msg.To {
		if err := client.Rcpt(to.String()); err != nil {
			return fmt.Errorf("smtpstore: RCPT TO %s: %w", to, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtpstore: DATA: %w", err)
	}

	if _, err := w.Write(wire); err != nil {
		w.Close()

		return fmt.Errorf("smtpstore: writing message: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("smtpstore: completing message: %w", err)
	}

	if err := client.Quit(); err != nil {
		return fmt.Errorf("smtpstore: QUIT: %w", err)
	}

	s.log.Debug("smtpstore: message accepted", "host", s.cfg.Host, "bytes", len(wire))

	return nil
}

// Check proves the relay is reachable and the credentials are accepted, without
// sending anything. An operator should be able to find out that submission is
// broken at a time of their choosing, not from the absence of an alert.
func (s *Store) Check(ctx context.Context) error {
	client, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	s.log.Info("smtpstore: relay reachable and authenticated", "host", s.cfg.Host, "port", s.cfg.Port)

	return client.Quit()
}

// connect dials, secures and authenticates.
func (s *Store) connect(ctx context.Context) (*smtp.Client, error) {
	address := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))

	// Refused here as well as in the config layer. This is the last point
	// before a password could go out in the clear, and a check at the edge that
	// depends on a caller having done its own is not a check.
	if s.cfg.Security == securityNone && !isLoopback(s.cfg.Host) {
		return nil, fmt.Errorf("smtpstore: refusing to speak plaintext to %s; that is only allowed for a relay on this machine", s.cfg.Host)
	}

	tlsConfig := tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}

	// A mail server on this machine almost always presents a self-signed
	// certificate for a name that is not "localhost". Verifying it would mean
	// refusing the one relay whose traffic provably never leaves the host —
	// so on loopback the certificate is used for encryption and not for
	// identity. Off loopback, verification stays mandatory.
	if isLoopback(s.cfg.Host) {
		tlsConfig.InsecureSkipVerify = true
	}

	dialer := net.Dialer{Timeout: s.cfg.Timeout}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("smtpstore: dialling %s: %w", address, err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(s.cfg.Timeout))
	}

	if s.cfg.Security == securityTLS {
		conn = tls.Client(conn, &tlsConfig)
	}

	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		conn.Close()

		return nil, fmt.Errorf("smtpstore: greeting from %s: %w", address, err)
	}

	if s.cfg.Security == securitySTARTTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			client.Close()

			return nil, fmt.Errorf("smtpstore: %s does not offer STARTTLS; refusing to send a password in the clear", address)
		}

		if err := client.StartTLS(&tlsConfig); err != nil {
			client.Close()

			return nil, fmt.Errorf("smtpstore: starting TLS with %s: %w", address, err)
		}
	}

	// No username means no authentication, which is the normal shape of a
	// local relay: it trusts the loopback connection rather than a password.
	// Nothing is sent that could be intercepted, so there is nothing to
	// protect and no reason to demand a credential that does not exist.
	if s.cfg.Username == "" {
		return client, nil
	}

	// PLAIN over an established TLS session. net/smtp refuses PLAIN on an
	// unencrypted connection, which is a guard rail worth keeping rather than
	// working around.
	auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	if err := client.Auth(auth); err != nil {
		client.Close()

		return nil, fmt.Errorf("smtpstore: authenticating to %s as %q: %w", address, s.cfg.Username, err)
	}

	return client, nil
}
