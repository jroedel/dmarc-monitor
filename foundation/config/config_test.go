package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jroedel/dmarc-monitor/foundation/config"
)

// minimal is the smallest file that should load: the six values that have no
// possible default, and nothing else.
const minimal = `
IMAP_USERNAME=reports@example.com
IMAP_PASSWORD=hunter2
SMTP_USERNAME=alerts@example.com
SMTP_PASSWORD=hunter3
ALERT_FROM=dmarc@example.com
ALERT_TO=webmaster@example.com
`

func write(t *testing.T, contents string, mode os.FileMode) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "credentials.env")
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	return path
}

func TestLoadMinimal(t *testing.T) {
	cfg, err := config.Load(write(t, minimal, 0o600))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	switch {
	case cfg.IMAPHost != "mail.your-server.de":
		t.Errorf("IMAP host = %q, want the Hetzner default", cfg.IMAPHost)
	case cfg.IMAPPort != 993:
		t.Errorf("IMAP port = %d, want 993", cfg.IMAPPort)
	case cfg.IMAPSecurity != config.SecurityTLS:
		t.Errorf("IMAP security = %q, want tls for port 993", cfg.IMAPSecurity)
	case cfg.SMTPSecurity != config.SecuritySTARTTLS:
		t.Errorf("SMTP security = %q, want starttls for port 587", cfg.SMTPSecurity)
	case cfg.AlertFloor.String() != "warning":
		t.Errorf("alert floor = %q, want warning", cfg.AlertFloor)
	case !cfg.MarkSeen:
		t.Error("MarkSeen defaulted to false; reports would be reprocessed forever")
	case len(cfg.AlertTo) != 1:
		t.Errorf("recipients = %v, want one", cfg.AlertTo)
	}
}

// The file holds two passwords. A group- or world-readable copy on a shared
// host is the whole compromise, so it must not load at all.
func TestRejectsLoosePermissions(t *testing.T) {
	_, err := config.Load(write(t, minimal, 0o644))
	if err == nil {
		t.Fatal("loaded a world-readable credentials file")
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("error does not tell the operator how to fix it: %v", err)
	}
}

// A typo'd key is a silently disabled setting, discovered on the day it
// mattered. It has to be a hard error.
func TestRejectsUnknownKey(t *testing.T) {
	_, err := config.Load(write(t, minimal+"ALERT_T0=typo@example.com\n", 0o600))
	if err == nil {
		t.Fatal("accepted an unknown key")
	}
	if !strings.Contains(err.Error(), "ALERT_T0") {
		t.Errorf("error does not name the offending key: %v", err)
	}
}

// An operator filling this in for the first time should learn about every
// problem in one run, not across four.
func TestReportsEveryProblemAtOnce(t *testing.T) {
	_, err := config.Load(write(t, `
IMAP_USERNAME=reports@example.com
IMAP_PASSWORD=hunter2
ALERT_FROM=not-an-address
ALERT_TO=webmaster@example.com
IMAP_PORT=nine-nine-three
ALERT_FLOOR=panic
`, 0o600))
	if err == nil {
		t.Fatal("accepted a file with three problems")
	}

	// SMTP_USERNAME is deliberately absent: a local relay wants no credentials,
	// so its absence is no longer a problem to report.
	for _, want := range []string{"IMAP_PORT", "ALERT_FLOOR", "ALERT_FROM"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
}

// The template documents each setting with a trailing comment. An operator who
// uncomments a line takes the comment with it, so the parser has to cope — this
// is the first thing that broke in real use.
func TestTrailingCommentsAreStripped(t *testing.T) {
	cfg, err := config.Load(write(t, minimal+`
IMAP_SECURITY=starttls           # tls (implicit, 993) or starttls (143/587)
IMAP_PORT=143  # not the default
IMAP_MAILBOX=INBOX.dmarc	# a tab before the hash counts too
`, 0o600))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	switch {
	case cfg.IMAPSecurity != config.SecuritySTARTTLS:
		t.Errorf("security = %q, want starttls", cfg.IMAPSecurity)
	case cfg.IMAPPort != 143:
		t.Errorf("port = %d, want 143", cfg.IMAPPort)
	case cfg.IMAPMailbox != "INBOX.dmarc":
		t.Errorf("mailbox = %q, want INBOX.dmarc", cfg.IMAPMailbox)
	}
}

// A '#' inside a password is a '#', not a comment. Only whitespace makes it one.
func TestHashInsideAValueSurvives(t *testing.T) {
	cfg, err := config.Load(write(t, `
IMAP_USERNAME=reports@example.com
IMAP_PASSWORD=hunter#2
SMTP_USERNAME=alerts@example.com
SMTP_PASSWORD="pass with # and spaces"
ALERT_FROM=dmarc@example.com
ALERT_TO=webmaster@example.com
`, 0o600))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	switch {
	case cfg.IMAPPassword != "hunter#2":
		t.Errorf("unquoted password mangled: %q", cfg.IMAPPassword)
	case cfg.SMTPPassword != "pass with # and spaces":
		t.Errorf("quoted password mangled: %q", cfg.SMTPPassword)
	}
}

func TestQuotedAndCommentedValues(t *testing.T) {
	cfg, err := config.Load(write(t, minimal+`
# a comment
IMAP_MAILBOX="INBOX.dmarc"
ALERT_SUBJECT_PREFIX='[dmarc prod]'
POLL_INTERVAL=90m
`, 0o600))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	switch {
	case cfg.IMAPMailbox != "INBOX.dmarc":
		t.Errorf("mailbox = %q, want the unquoted value", cfg.IMAPMailbox)
	case cfg.AlertSubjectPrefix != "[dmarc prod]":
		t.Errorf("subject prefix = %q, want the unquoted value", cfg.AlertSubjectPrefix)
	case cfg.PollInterval.Minutes() != 90:
		t.Errorf("poll interval = %v, want 90m", cfg.PollInterval)
	}
}

func TestMissingFileIsRecognisable(t *testing.T) {
	_, err := config.Load(filepath.Join(t.TempDir(), "absent.env"))
	if err == nil {
		t.Fatal("loaded a file that does not exist")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error is not the recognisable not-found error: %v", err)
	}
}

// The template is the primary documentation, so it has to survive its own
// parser — and it must not ship with a password in it.
func TestTemplateLoadsAfterFillingInTheRequiredKeys(t *testing.T) {
	filled := config.Template + minimal

	if _, err := config.Load(write(t, filled, 0o600)); err != nil {
		t.Fatalf("the shipped template does not parse: %v", err)
	}

	if _, err := config.Load(write(t, config.Template, 0o600)); err == nil {
		t.Error("the untouched template loaded; it should demand the required keys")
	}
}

func TestInitRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "credentials.env")

	if err := config.Init(path); err != nil {
		t.Fatalf("Init: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("template written mode %#o, want 0600", got)
	}

	if err := config.Init(path); err == nil {
		t.Error("Init overwrote an existing credentials file")
	}
}

// A relay on this machine is the arrangement that lets an alert go out as the
// host's own mail — SPF standing and DKIM signature included — so it has to be
// configurable without credentials.
func TestLocalRelayNeedsNoCredentials(t *testing.T) {
	cfg, err := config.Load(write(t, `
IMAP_USERNAME=reports@example.com
IMAP_PASSWORD=hunter2
SMTP_HOST=localhost
SMTP_PORT=25
ALERT_FROM=dmarc@example.com
ALERT_TO=webmaster@example.com
`, 0o600))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	switch {
	case cfg.SMTPSecurity != config.SecurityNone:
		t.Errorf("security = %q, want none for port 25 on loopback", cfg.SMTPSecurity)
	case cfg.SMTPUsername != "":
		t.Errorf("username = %q, want empty", cfg.SMTPUsername)
	}
}

// Plaintext off the loopback address is a conversation strangers can read.
func TestPlaintextIsRefusedForRemoteRelays(t *testing.T) {
	_, err := config.Load(write(t, minimal+`
SMTP_HOST=mail.your-server.de
SMTP_SECURITY=none
`, 0o600))
	if err == nil {
		t.Fatal("accepted plaintext to a remote relay")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("error does not explain the refusal: %v", err)
	}
}

// A password on a plaintext connection would be handed over in the clear, even
// on loopback where the rest is harmless.
func TestPasswordOverPlaintextIsRefused(t *testing.T) {
	_, err := config.Load(write(t, `
IMAP_USERNAME=reports@example.com
IMAP_PASSWORD=hunter2
SMTP_HOST=127.0.0.1
SMTP_SECURITY=none
SMTP_USERNAME=alerts@example.com
SMTP_PASSWORD=hunter3
ALERT_FROM=dmarc@example.com
ALERT_TO=webmaster@example.com
`, 0o600))
	if err == nil {
		t.Fatal("accepted a password on a plaintext connection")
	}
	if !strings.Contains(err.Error(), "clear") {
		t.Errorf("error does not explain the refusal: %v", err)
	}
}

// Half a credential is a typo, and the half present would be sent to a server
// not expecting it.
func TestHalfAnSMTPCredentialIsRefused(t *testing.T) {
	for name, extra := range map[string]string{
		"username without password": "SMTP_USERNAME=alerts@example.com\n",
		"password without username": "SMTP_PASSWORD=hunter3\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := config.Load(write(t, `
IMAP_USERNAME=reports@example.com
IMAP_PASSWORD=hunter2
ALERT_FROM=dmarc@example.com
ALERT_TO=webmaster@example.com
`+extra, 0o600))
			if err == nil {
				t.Error("accepted half a credential")
			}
		})
	}
}

// Reading the mailbox always sends a password, so it has no plaintext mode.
func TestIMAPHasNoPlaintextMode(t *testing.T) {
	_, err := config.Load(write(t, minimal+"IMAP_SECURITY=none\n", 0o600))
	if err == nil {
		t.Fatal("accepted plaintext IMAP")
	}
}

// The remote default must not have moved.
func TestRemoteRelayStillDefaultsToSTARTTLS(t *testing.T) {
	cfg, err := config.Load(write(t, minimal, 0o600))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SMTPSecurity != config.SecuritySTARTTLS {
		t.Errorf("security = %q, want starttls", cfg.SMTPSecurity)
	}
}
