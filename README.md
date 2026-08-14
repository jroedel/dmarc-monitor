# dmarc-monitor

Reads DMARC aggregate reports out of a mailbox and emails the webmaster when —
and only when — something needs doing about them.

DMARC reports are XML, they arrive daily from every large receiver, and they are
almost entirely routine. Forwarding them to a person does not work: the one
report in fifty that matters looks exactly like the other forty-nine, so the
folder gets a filter rule and stops being read. This program reads them instead,
applies a fixed set of rules, and sends at most one plain-text email when a rule
fires. On a healthy domain it sends nothing for months. That silence is the
feature.

## What it alerts on

| Finding | Severity | Meaning |
|---|---|---|
| `blocked-known-source` | critical | A server this domain has used before is having its mail quarantined or rejected. Mail is being lost right now. |
| `domain-failure-rate` | warning / critical | The domain as a whole is failing more than the threshold, with no single sender responsible — usually a broken SPF include or a removed DKIM record. |
| `failing-known-source` | warning | A known sender is failing authentication while the policy is still `p=none`. The window in which the fix is free. |
| `new-source` | notice / warning | An IP that has never sent for this domain is now sending at volume. Either a service somebody signed up for, or spoofing. |
| `ready-to-enforce` | notice | Everything passes, at volume, from several sources — and the policy is still `p=none`, protecting nothing. |

Nothing below `ALERT_FLOOR` (default `warning`) is sent. A finding that has
already been sent stays quiet for `ALERT_COOLDOWN` (default 72h), per finding,
so an unfixed problem does not mail the webmaster daily while a *new* problem
still gets through immediately.

Deliberately silent: failures the receiver itself excused (`forwarded`,
`mailing_list`), mail whose header-from does not align with the domain at all,
every sender on the very first run, and any rate computed over fewer than
`TRIAGE_MIN_VOLUME` messages.

## Getting started

```bash
make build                     # or: go build ./cmd/dmarc-monitor
./dmarc-monitor -init-credentials
$EDITOR ~/.local/share/dmarc-monitor/credentials.env
./dmarc-monitor -check         # proves the mailbox and relay both work
./dmarc-monitor -once -dry-run # full cycle, prints the alert, sends nothing
./dmarc-monitor -once          # for real
```

Only unread messages are examined — `\Seen` is what makes the mailbox its own
queue, and a report a human opened by hand is one they are looking at. For a
first run over a mailbox that already holds an archive of reports, add
`-include-seen`. Nothing is double-alerted either way; the checkpoint
deduplicates on the reporter's own report id.

The credentials file is the only configuration. It documents every setting
inline — read it rather than this section. It must be mode 0600 or the program
refuses to start, and an unknown key is a hard error, so a typo can never
silently disable a setting.

Defaults are Hetzner's (`mail.your-server.de`, IMAP 993 implicit TLS, submission
587 STARTTLS). TLS is mandatory in both modes and certificates are always
verified; there is no plaintext path.

Six values have no default and must be filled in: `IMAP_USERNAME`,
`IMAP_PASSWORD`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `ALERT_FROM`, `ALERT_TO`.

`ALERT_FROM` must be an address the relay will send as. If it fails your own SPF
or DKIM, the alert about DMARC gets quarantined.

## Running it unattended

`-watch` polls on `POLL_INTERVAL` (default 6h). A systemd timer running `-once`
is the better arrangement — it survives reboots and leaves the logging to the
journal.

```ini
# ~/.config/systemd/user/dmarc-monitor.service
[Unit]
Description=Check DMARC aggregate reports

[Service]
Type=oneshot
ExecStart=%h/bin/dmarc-monitor -once -log json
```

```ini
# ~/.config/systemd/user/dmarc-monitor.timer
[Unit]
Description=Check DMARC aggregate reports twice a day

[Timer]
OnCalendar=06,18:00
Persistent=true

[Install]
WantedBy=timers.target
```

Reporters send once a day. Polling faster than a few hours only annoys their
servers.

## How a cycle works

The order is the correctness argument, and every shortcut in it loses mail:

1. **Fetch, read-only.** Unread messages are peeked, never flagged.
2. **Drop** reports already processed on an earlier run, keyed by the reporter's
   own report id.
3. **Triage**, with the checkpoint's memory of known senders folded in.
4. **Drop** findings still inside their cooldown; re-grade what is left.
5. **Send** — or, with `-dry-run`, print.
6. **Only now**: learn the senders, record the findings as sent, mark the
   messages `\Seen` (or move them to `IMAP_MOVE_TO`).

Nothing is remembered until the human has been told. A crash anywhere in 1–5
leaves the mailbox and the state file untouched and the next run repeats the
work. Flag-first would turn one crash into a permanently missed alert that
nothing would ever re-raise.

State lives in `~/.local/state/dmarc-monitor/state.json` — processed report ids,
known senders per domain, and when each finding was last sent. It is plain JSON
so it can be read when an alert did or did not arrive unexpectedly. Deleting it
costs one noisy run, not correctness.

## The local model

Optional, off by default, and strictly limited: with `LLM_ENABLED=true` a local
model served by [kronk](https://github.com/ardanlabs/kronk) writes the opening
paragraph of an alert **that was already going to be sent**.

It cannot raise a severity, invent a finding, or suppress one. Every decision is
made by the deterministic rules before the model is asked anything, and the
model is only asked at all when an alert is going out. If it is slow, down, or
confidently wrong, the alert goes out with the rule-generated summary instead —
the failure costs prose, not correctness.

This is the only arrangement worth having. A model that could decide would be a
monitor that alerts differently on Tuesday, and a webmaster who learns not to
trust it.

```bash
go install github.com/ardanlabs/kronk/cmd/kronk@latest
kronk server start          # OpenAI-compatible, port 11435
```

Nothing leaves the machine: the prompt carries domain names, IPs and message
counts, which is why the endpoint defaults to loopback and there is no notion of
an API key.

## Layout

```
cmd/dmarc-monitor      flags, wiring, the -check and -init-credentials paths
app/monitor            the cycle; the only package that knows all three domains
business/domain/report    reportbus  + stores/imapstore
business/domain/triage    triagebus  + stores/kronkllm
business/domain/alert     alertbus   + stores/smtpstore
business/types            domainname, authresult, disposition, severity, email
foundation/dmarcxml       RFC 7489 wire format, zip/gzip unwrapping
foundation/config         the credentials file
foundation/checkpoint     what carries over between runs
foundation/logger         slog setup
```

Business domains never import each other; `app/monitor` composes them, and
`app/monitor/convert.go` holds every crossing. Primitives live at the edges,
strong types only in the Business layer. See `AGENTS.md`.

## Known issue

`make test` currently fails at `vuln-check`: Go 1.26.5 is installed and five
standard-library advisories (GO-2026-6218, -6090, -6088, -5972, -5026, in
`net/url`, `crypto/tls`, `encoding/xml`, `encoding/asn1` and `net/http`) are
fixed in 1.26.6. All five are reachable from this program — it parses XML from
strangers and speaks TLS to two servers — so the fix is to upgrade the
toolchain, not to suppress the check. `make test-unit lint` passes.

## Development

```bash
make test           # unit tests + lint + govulncheck
make test-unit      # offline
make lint           # go vet + gofmt check
```
