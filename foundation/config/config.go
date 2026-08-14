// Package config loads the one file that holds everything this program must not
// have compiled into it: the mailbox it reads, the relay it sends through, the
// passwords for both, and the thresholds that decide when a human is worth
// disturbing.
//
// The file lives outside the repository — ~/.local/share/dmarc-monitor/ by
// default, XDG_DATA_HOME if set — and is refused unless its mode is 0600. That
// check is not decoration: this file grants read access to a mailbox and the
// ability to send mail as the domain, and a world-readable copy on a shared
// host is the whole compromise. It is cheaper to fail at startup than to
// discover it later.
//
// Format is deliberately KEY=value with # comments rather than TOML or YAML:
// it needs no dependency, it is what an operator expects a credentials file to
// look like, and it can be pasted into a shell to debug a connection by hand.
// Unknown keys are an error, not a warning — a typo'd ALERT_T0 that silently
// left the alert address empty would be discovered the day it mattered.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jroedel/dmarc-monitor/business/types/email"
	"github.com/jroedel/dmarc-monitor/business/types/severity"
)

// ErrNotFound is returned by Load when the credentials file does not exist, so
// that the command can tell the operator to run -init-credentials rather than
// printing a bare ENOENT.
var ErrNotFound = errors.New("config: credentials file not found")

// Config is the whole of the program's configuration.
//
// It is one flat struct rather than a tree because it is loaded from one flat
// file, and because every grouping considered here (IMAP/SMTP/triage) would
// have been a naming convention on the keys anyway.
type Config struct {
	// Mailbox to read reports from.
	IMAPHost     string
	IMAPPort     int
	IMAPUsername string
	IMAPPassword string
	IMAPMailbox  string
	IMAPSecurity Security

	// What to do with a message once its reports have been read. Marking it
	// seen is what stops the next run from alerting on it again, so it is on by
	// default; a move target is offered for operators who prefer the mailbox to
	// empty itself into an archive folder.
	MarkSeen bool
	MoveTo   string

	// Relay to send the alert through. Separate from the IMAP account on
	// purpose: the mailbox that receives reports is often a role address that
	// cannot send, and the alert must go out even when it cannot.
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPSecurity Security

	// Who the alert is from, who it goes to, and how its subject is prefixed so
	// a webmaster can filter on it.
	AlertFrom          email.Email
	AlertTo            []email.Email
	AlertSubjectPrefix string

	// AlertFloor is the severity at which an email is actually sent. Everything
	// below it is logged and forgotten. This is the single most important knob
	// in the file: raise it and the program goes quiet, lower it and it becomes
	// the noise it was written to replace.
	AlertFloor severity.Severity

	// Triage thresholds. Documented at length in the template.
	FailureRateThreshold float64
	MinimumVolume        int
	NewSourceVolume      int

	// AlertCooldown is how long the same finding stays quiet after being sent.
	// Reports overlap and repeat: without this, one unresolved misconfiguration
	// mails the webmaster every day until they filter the alerts away, which is
	// the exact failure this program is meant to avoid.
	AlertCooldown time.Duration

	// PollInterval is how often the mailbox is checked when running as a daemon.
	// Reporters send once a day; anything under a few minutes is pure noise
	// against someone else's IMAP server.
	PollInterval time.Duration

	// LLM enrichment. Off unless Enabled — the deterministic rules decide
	// whether to alert either way, and a model that is down must never be able
	// to stop an alert going out.
	LLMEnabled  bool
	LLMEndpoint string
	LLMModel    string
	LLMTimeout  time.Duration
}

// Security is how a connection is protected.
type Security string

const (
	// SecurityTLS is implicit TLS from the first byte: IMAP 993, SMTP 465.
	SecurityTLS Security = "tls"

	// SecuritySTARTTLS opens in the clear and upgrades: SMTP 587, IMAP 143.
	// The upgrade is mandatory here — a server that will not do it is refused
	// rather than silently spoken to in plaintext.
	SecuritySTARTTLS Security = "starttls"
)

// DefaultPath returns where the credentials file lives: $XDG_DATA_HOME if the
// variable is set, otherwise ~/.local/share.
func DefaultPath() (string, error) {
	dir, err := dataDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, "credentials.env"), nil
}

// Load reads, parses and validates the credentials file at path.
func Load(path string) (Config, error) {
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return Config{}, fmt.Errorf("%w at %s", ErrNotFound, path)
	case err != nil:
		return Config{}, fmt.Errorf("config: stat %s: %w", path, err)
	case info.Mode().Perm()&0o077 != 0:
		return Config{}, fmt.Errorf("config: %s is mode %#o; it holds passwords, so run: chmod 600 %s", path, info.Mode().Perm(), path)
	}

	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: opening %s: %w", path, err)
	}
	defer f.Close()

	values, err := parse(f)
	if err != nil {
		return Config{}, fmt.Errorf("config: %s: %w", path, err)
	}

	cfg, err := build(values)
	if err != nil {
		return Config{}, fmt.Errorf("config: %s: %w", path, err)
	}

	return cfg, nil
}

// parse turns the file into a key/value map, rejecting anything it cannot
// account for.
func parse(r io.Reader) (map[string]string, error) {
	values := make(map[string]string)

	scanner := bufio.NewScanner(r)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		key, value, found := strings.Cut(text, "=")
		if !found {
			return nil, fmt.Errorf("line %d: %q is neither a comment nor KEY=value", line, text)
		}

		key = strings.TrimSpace(key)
		if !known[key] {
			return nil, fmt.Errorf("line %d: unknown key %q", line, key)
		}

		values[key] = parseValue(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading: %w", err)
	}

	return values, nil
}

// parseValue turns the right-hand side of a KEY=value line into the value.
//
// Two things happen here, and both exist because of how the shipped template
// reads. Quotes are stripped, so a password with leading or trailing spaces can
// be written down unambiguously. And an unquoted value has any trailing
// `# comment` removed — the template documents the alternatives inline, like
//
//	IMAP_SECURITY=tls           # tls (implicit, 993) or starttls
//
// and an operator who uncomments that line takes the comment with it. Reading
// the whole remainder as the value would fail on the one file the program
// itself wrote.
//
// A '#' only starts a comment when preceded by whitespace, so a password of
// `hunter#2` survives. A password that genuinely contains ` #` must be quoted,
// which the template says.
func parseValue(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}

	if quote := s[0]; quote == '"' || quote == '\'' {
		if end := strings.IndexByte(s[1:], quote); end >= 0 {
			return s[1 : end+1]
		}

		// An unterminated quote is far more likely to be a password that starts
		// with one than a mistake, so it is kept whole rather than rejected.
		return s
	}

	if hash := indexComment(s); hash >= 0 {
		s = strings.TrimSpace(s[:hash])
	}

	return s
}

// indexComment finds a '#' that begins a trailing comment: one preceded by
// whitespace. Returns -1 when there is none.
func indexComment(s string) int {
	for i := 1; i < len(s); i++ {
		if s[i] == '#' && (s[i-1] == ' ' || s[i-1] == '\t') {
			return i
		}
	}

	return -1
}

func dataDir() (string, error) {
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return filepath.Join(dir, "dmarc-monitor"), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("config: locating home directory: %w", err)
	}

	return filepath.Join(home, ".local", "share", "dmarc-monitor"), nil
}

// parseInt, parseFloat, parseBool and parseDuration all take the value's own
// default, so that an absent key and an empty value mean the same thing: use
// the default. Only a present, non-empty, unparsable value is an error.
func parseInt(values map[string]string, key string, def int) (int, error) {
	raw := values[key]
	if raw == "" {
		return def, nil
	}

	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a number", key, raw)
	}

	return n, nil
}

func parseFloat(values map[string]string, key string, def float64) (float64, error) {
	raw := values[key]
	if raw == "" {
		return def, nil
	}

	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a number", key, raw)
	}

	return f, nil
}

func parseBool(values map[string]string, key string, def bool) (bool, error) {
	raw := values[key]
	if raw == "" {
		return def, nil
	}

	b, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s: %q is not true or false", key, raw)
	}

	return b, nil
}

func parseDuration(values map[string]string, key string, def time.Duration) (time.Duration, error) {
	raw := values[key]
	if raw == "" {
		return def, nil
	}

	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a duration like 15m or 24h", key, raw)
	}

	return d, nil
}
