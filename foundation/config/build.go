package config

import (
	"cmp"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jroedel/dmarc-monitor/business/types/email"
	"github.com/jroedel/dmarc-monitor/business/types/severity"
)

// Defaults are Hetzner's mail service, since that is the mailbox this was
// written for: IMAP over implicit TLS on 993, submission over STARTTLS on 587,
// both on mail.your-server.de. Every one of them is overridable; none of them
// includes a credential.
const (
	defaultIMAPHost     = "mail.your-server.de"
	defaultIMAPPort     = 993
	defaultIMAPMailbox  = "INBOX"
	defaultSMTPHost     = "mail.your-server.de"
	defaultSMTPPort     = 587
	defaultSubjectPfx   = "[dmarc]"
	defaultPollInterval = 6 * time.Hour
	defaultCooldown     = 72 * time.Hour
	defaultFailureRate  = 0.02
	defaultMinVolume    = 25
	defaultNewSourceVol = 50
	defaultLLMEndpoint  = "http://127.0.0.1:11435"
	defaultLLMModel     = "gpt-oss:20b"
	defaultLLMTimeout   = 2 * time.Minute
)

// known is every key the file may contain. Anything else is a typo, and a typo
// in a credentials file is a silently disabled feature.
var known = map[string]bool{
	"IMAP_HOST":     true,
	"IMAP_PORT":     true,
	"IMAP_USERNAME": true,
	"IMAP_PASSWORD": true,
	"IMAP_MAILBOX":  true,
	"IMAP_SECURITY": true,

	"IMAP_MARK_SEEN": true,
	"IMAP_MOVE_TO":   true,

	"SMTP_HOST":     true,
	"SMTP_PORT":     true,
	"SMTP_USERNAME": true,
	"SMTP_PASSWORD": true,
	"SMTP_SECURITY": true,

	"ALERT_FROM":           true,
	"ALERT_TO":             true,
	"ALERT_SUBJECT_PREFIX": true,
	"ALERT_FLOOR":          true,
	"ALERT_COOLDOWN":       true,

	"TRIAGE_FAILURE_RATE":      true,
	"TRIAGE_MIN_VOLUME":        true,
	"TRIAGE_NEW_SOURCE_VOLUME": true,

	"POLL_INTERVAL": true,

	"LLM_ENABLED":  true,
	"LLM_ENDPOINT": true,
	"LLM_MODEL":    true,
	"LLM_TIMEOUT":  true,
}

// build turns parsed key/values into a validated Config.
//
// Every problem is collected and reported together rather than returned at the
// first one. An operator filling this file in for the first time should learn
// about all four things they got wrong in one run, not across four.
func build(values map[string]string) (Config, error) {
	var errs []error

	fail := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	cfg := Config{
		IMAPHost:     cmp.Or(values["IMAP_HOST"], defaultIMAPHost),
		IMAPUsername: values["IMAP_USERNAME"],
		IMAPPassword: values["IMAP_PASSWORD"],
		IMAPMailbox:  cmp.Or(values["IMAP_MAILBOX"], defaultIMAPMailbox),
		MoveTo:       values["IMAP_MOVE_TO"],

		SMTPHost:     cmp.Or(values["SMTP_HOST"], defaultSMTPHost),
		SMTPUsername: values["SMTP_USERNAME"],
		SMTPPassword: values["SMTP_PASSWORD"],

		AlertSubjectPrefix: cmp.Or(values["ALERT_SUBJECT_PREFIX"], defaultSubjectPfx),

		LLMEndpoint: cmp.Or(values["LLM_ENDPOINT"], defaultLLMEndpoint),
		LLMModel:    cmp.Or(values["LLM_MODEL"], defaultLLMModel),
	}

	var err error

	cfg.IMAPPort, err = parseInt(values, "IMAP_PORT", defaultIMAPPort)
	fail(err)

	cfg.SMTPPort, err = parseInt(values, "SMTP_PORT", defaultSMTPPort)
	fail(err)

	cfg.IMAPSecurity, err = parseSecurity(values, "IMAP_SECURITY", cfg.IMAPPort)
	fail(err)

	cfg.SMTPSecurity, err = parseSecurity(values, "SMTP_SECURITY", cfg.SMTPPort)
	fail(err)

	cfg.MarkSeen, err = parseBool(values, "IMAP_MARK_SEEN", true)
	fail(err)

	cfg.PollInterval, err = parseDuration(values, "POLL_INTERVAL", defaultPollInterval)
	fail(err)

	cfg.AlertCooldown, err = parseDuration(values, "ALERT_COOLDOWN", defaultCooldown)
	fail(err)

	cfg.FailureRateThreshold, err = parseFloat(values, "TRIAGE_FAILURE_RATE", defaultFailureRate)
	fail(err)

	cfg.MinimumVolume, err = parseInt(values, "TRIAGE_MIN_VOLUME", defaultMinVolume)
	fail(err)

	cfg.NewSourceVolume, err = parseInt(values, "TRIAGE_NEW_SOURCE_VOLUME", defaultNewSourceVol)
	fail(err)

	cfg.LLMEnabled, err = parseBool(values, "LLM_ENABLED", false)
	fail(err)

	cfg.LLMTimeout, err = parseDuration(values, "LLM_TIMEOUT", defaultLLMTimeout)
	fail(err)

	cfg.AlertFloor, err = parseSeverity(values, "ALERT_FLOOR", severity.Warning)
	fail(err)

	cfg.AlertFrom, err = parseAddress(values, "ALERT_FROM")
	fail(err)

	cfg.AlertTo, err = parseAddressList(values, "ALERT_TO")
	fail(err)

	fail(requireFields(cfg))
	fail(validateRanges(cfg))

	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}

	return cfg, nil
}

// requireFields checks the values that have no sensible default, because they
// name an account or a person.
func requireFields(cfg Config) error {
	var missing []string

	for _, f := range []struct {
		key   string
		empty bool
	}{
		{"IMAP_USERNAME", cfg.IMAPUsername == ""},
		{"IMAP_PASSWORD", cfg.IMAPPassword == ""},
		{"SMTP_USERNAME", cfg.SMTPUsername == ""},
		{"SMTP_PASSWORD", cfg.SMTPPassword == ""},
	} {
		if f.empty {
			missing = append(missing, f.key)
		}
	}

	if len(missing) == 0 {
		return nil
	}

	return fmt.Errorf("required and empty: %s", strings.Join(missing, ", "))
}

func validateRanges(cfg Config) error {
	var errs []error

	switch {
	case cfg.FailureRateThreshold < 0 || cfg.FailureRateThreshold > 1:
		errs = append(errs, fmt.Errorf("TRIAGE_FAILURE_RATE: %v is not a fraction between 0 and 1", cfg.FailureRateThreshold))
	}

	if cfg.MinimumVolume < 1 {
		errs = append(errs, fmt.Errorf("TRIAGE_MIN_VOLUME: %d is below 1; a rate over zero messages is meaningless", cfg.MinimumVolume))
	}

	if cfg.PollInterval < time.Minute {
		errs = append(errs, fmt.Errorf("POLL_INTERVAL: %v is under a minute; reporters send once a day", cfg.PollInterval))
	}

	return errors.Join(errs...)
}

// parseSecurity defaults from the port, because the port is what an operator
// actually thinks in: 993 and 465 are implicit TLS, everything else upgrades.
func parseSecurity(values map[string]string, key string, port int) (Security, error) {
	switch raw := strings.ToLower(values[key]); raw {
	case "":
		if port == 993 || port == 465 {
			return SecurityTLS, nil
		}

		return SecuritySTARTTLS, nil

	case string(SecurityTLS), "ssl", "implicit":
		return SecurityTLS, nil

	case string(SecuritySTARTTLS):
		return SecuritySTARTTLS, nil

	default:
		return "", fmt.Errorf("%s: %q is not tls or starttls", key, raw)
	}
}

func parseSeverity(values map[string]string, key string, def severity.Severity) (severity.Severity, error) {
	raw := values[key]
	if raw == "" {
		return def, nil
	}

	sev, err := severity.Parse(strings.ToLower(raw))
	if err != nil {
		return severity.Severity{}, fmt.Errorf("%s: %w", key, err)
	}

	return sev, nil
}

func parseAddress(values map[string]string, key string) (email.Email, error) {
	raw := values[key]
	if raw == "" {
		return email.Email{}, fmt.Errorf("%s: required and empty", key)
	}

	addr, err := email.Parse(raw)
	if err != nil {
		return email.Email{}, fmt.Errorf("%s: %w", key, err)
	}

	return addr, nil
}

// parseAddressList accepts a comma-separated list, so that a second webmaster
// can be added without a second key.
func parseAddressList(values map[string]string, key string) ([]email.Email, error) {
	raw := strings.TrimSpace(values[key])
	if raw == "" {
		return nil, fmt.Errorf("%s: required and empty; nobody would be told", key)
	}

	var (
		addrs []email.Email
		errs  []error
	)

	for part := range strings.SplitSeq(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		addr, err := email.Parse(part)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", key, err))
			continue
		}

		addrs = append(addrs, addr)
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s: no addresses", key)
	}

	return addrs, nil
}
