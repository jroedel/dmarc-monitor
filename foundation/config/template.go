package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrExists is returned by Init when a credentials file is already in place.
// Overwriting one would destroy passwords that may exist nowhere else.
var ErrExists = errors.New("config: credentials file already exists")

// Init writes the commented template to path, creating the directory, and
// refuses to touch an existing file. Both the directory and the file are
// created 0700/0600 from the start rather than chmod'ed afterwards — there must
// be no window in which the file exists and is readable.
func Init(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%w at %s", ErrExists, path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("config: stat %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("config: creating %s: %w", filepath.Dir(path), err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("config: creating %s: %w", path, err)
	}
	defer f.Close()

	if _, err := f.WriteString(Template); err != nil {
		return fmt.Errorf("config: writing %s: %w", path, err)
	}

	return nil
}

// Template is the annotated credentials file. It is the primary documentation
// for every knob in this program: the operator reads it in the file they are
// already editing, not in a README they would have to go and find.
const Template = `# dmarc-monitor credentials and settings.
#
# This file holds passwords. Keep it mode 0600 -- the program refuses to start
# if it is anything else.
#
# It belongs beside the binary, which on a server means ~/dmarc-monitor/, so
# that one directory holds the whole installation. It is never read from the
# repository. (A file left at the older ~/.local/share/dmarc-monitor/ location
# is still honoured, so an existing install keeps working.)
#
# Format: KEY=value, one per line. Blank lines and #-comments are ignored,
# including a trailing comment after a value -- so uncommenting a line below
# and leaving its explanation attached does the right thing.
#
# Quote a value ("...", '...') if it has leading or trailing spaces, or if it
# contains a space followed by a #. A password like hunter#2 needs no quotes.
#
# An unknown key is a hard error, so a typo can never silently disable a
# setting. Commented-out keys show the default; delete the # to change one.

# ---------------------------------------------------------------- the mailbox
# Where the DMARC aggregate reports arrive. Defaults are Hetzner's.
#
# IMAP_MAILBOX can be a subfolder -- if a sieve rule files reports away from
# the inbox, name that folder here, with the server's own separator
# (Hetzner/Dovecot: "INBOX.dmarc").

#IMAP_HOST=mail.your-server.de
#IMAP_PORT=993
#IMAP_SECURITY=tls           # tls (implicit, 993) or starttls (143/587)
#IMAP_MAILBOX=INBOX
IMAP_USERNAME=
IMAP_PASSWORD=

# What to do with a report message once it has been read successfully.
# Marking it seen is what stops tomorrow's run from processing it again, so
# leaving this false means every report is re-read on every poll. If a folder
# is named in IMAP_MOVE_TO the message is moved there instead of just flagged;
# the folder must already exist.

#IMAP_MARK_SEEN=true
#IMAP_MOVE_TO=

# ------------------------------------------------------------------ the relay
# Where the alert is sent from. Separate credentials on purpose: the address
# that receives reports is often a role account that cannot send.
#
# If this machine runs its own mail server, prefer it over a remote relay:
#
#   SMTP_HOST=localhost
#   SMTP_PORT=25
#   (leave SMTP_USERNAME and SMTP_PASSWORD empty)
#
# An alert handed to the local mail server goes out as this host's own mail,
# with the SPF standing and the DKIM signature the host already has. The same
# alert pushed through someone else's relay has neither -- and once the domain
# moves to p=quarantine or p=reject, that is the mail that gets quarantined.
# The alert about DMARC failing is a poor thing to lose to DMARC.
#
# SMTP_SECURITY is tls (implicit, 465), starttls (587), or none. It defaults
# from the port and the host: 465 is tls, port 25 on this machine is none, and
# anything else upgrades with starttls. Plaintext is accepted only for a relay
# on the loopback address, where there is no wire to intercept; it is refused
# for any other host, and refused outright if a password is set.

#SMTP_HOST=mail.your-server.de
#SMTP_PORT=587
#SMTP_SECURITY=starttls      # starttls (587), tls (465), or none (local relay)
SMTP_USERNAME=
SMTP_PASSWORD=

# ------------------------------------------------------------------ the alert
# ALERT_FROM must be an address the relay is willing to send as -- if it fails
# your own SPF or DKIM, the alert about DMARC will itself be quarantined.
# ALERT_TO may be a comma-separated list.

ALERT_FROM=
ALERT_TO=
#ALERT_SUBJECT_PREFIX=[dmarc]

# The severity at which an email is actually sent. Everything below is logged
# and dropped. This is the volume knob for the whole program:
#
#   info      every report, however boring         -- do not use
#   notice    a new sending source appeared, authenticating cleanly
#   warning   mail is failing authentication, policy still lets it through
#   critical  mail is being quarantined or rejected, or an unauthenticated
#             flood is claiming the domain
#
# warning is the default: it catches a broken sender while p=none still means
# nothing is being lost, which is the window in which the fix is free.

#ALERT_FLOOR=warning

# How long the same finding stays quiet after it has been sent once. Reports
# overlap and repeat daily; without a cooldown an unresolved misconfiguration
# would mail the webmaster every day until they filtered the alerts away.

#ALERT_COOLDOWN=72h

# Mail the same recipients on the first scheduled run of a newly deployed
# build. Rare -- only when a deploy actually lands -- and it is how a deploy is
# verified from the server's side: proof the pipeline reached it, without
# logging in to check. Set to false once that stops being interesting.

#ALERT_ON_UPDATE=true

# ------------------------------------------------------------------- triage
# TRIAGE_FAILURE_RATE is the fraction of messages that may fail DMARC before a
# domain is considered to have a problem. 0.02 = 2%. Forwarding breaks SPF as a
# matter of course, so a small non-zero rate is normal on any real domain.
#
# TRIAGE_MIN_VOLUME is the number of messages a source must send before a rate
# is computed at all -- 1 failure out of 2 messages is 50% and means nothing.
#
# TRIAGE_NEW_SOURCE_VOLUME is how much mail an IP the domain has never used
# before must send to be worth mentioning on its own.

#TRIAGE_FAILURE_RATE=0.02
#TRIAGE_MIN_VOLUME=25
#TRIAGE_NEW_SOURCE_VOLUME=50

# How often to check the mailbox when running as a daemon (-watch). Reporters
# send once a day; polling faster than a few hours only annoys their servers.

#POLL_INTERVAL=6h

# ---------------------------------------------------------------------- LLM
# Optional. A local model NEVER decides whether to alert -- the rules above do
# that, deterministically -- it only writes the human-readable explanation at
# the top of an alert that was already going to be sent. If the model is slow,
# wrong or down, the alert goes out with the plain rule-generated summary.
#
# LLM_ENDPOINT is an OpenAI-compatible /v1/chat/completions server, which is
# what kronk (github.com/ardanlabs/kronk) exposes when serving a local model.

#LLM_ENABLED=false
#LLM_ENDPOINT=http://127.0.0.1:11435
#LLM_MODEL=gpt-oss:20b
#LLM_TIMEOUT=2m
`
