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

That is a real trap once the domain moves past `p=none`, and the fix is to send
through the mail server on the machine itself rather than a remote relay:

```bash
SMTP_HOST=localhost
SMTP_PORT=25
SMTP_USERNAME=
SMTP_PASSWORD=
```

An alert handed to the local mail server leaves as the host's own mail, with the
SPF standing and DKIM signature the host already has. Pushed through someone
else's relay it has neither, and is exactly the mail a tightened policy
quarantines. Plaintext is accepted only for a loopback relay — there is no wire
to intercept — and is refused for any other host, or if a password is set.

## Deploying it

Two steps. No binary to download by hand, nothing to install.

**1. Write the credentials** to `~/dmarc-monitor/credentials.env` on the server:

```bash
mkdir -p ~/dmarc-monitor && chmod 700 ~/dmarc-monitor
cat > ~/dmarc-monitor/credentials.env <<'EOF'
IMAP_HOST=mail.your-server.de
IMAP_USERNAME=dmarc@yourdomain.example
IMAP_PASSWORD=...
SMTP_HOST=mail.your-server.de
SMTP_USERNAME=alerts@yourdomain.example
SMTP_PASSWORD=...
ALERT_FROM=dmarc@yourdomain.example
ALERT_TO=webmaster@yourdomain.example
EOF
chmod 600 ~/dmarc-monitor/credentials.env
```

Those are the only keys without a default. Everything else is documented in the
annotated template — and if you would rather have that than the block above,
skip this step, let step 2 run once, and it writes the template there for you.

**2. Add the crontab entry** with `crontab -e` (`deploy/crontab.example` is the
annotated version, and `make crontab` prints it):

```cron
MAILTO=you@example.com

0 * * * * H="$(TZ=America/Chicago date +\%H)"; [ "$H" = 08 ] || [ "$H" = 20 ] || exit 0; D="$HOME/dmarc-monitor"; B="$D/dmarc-monitor"; mkdir -p "$D"; [ -x "$B" ] || { curl -fsSL "https://github.com/jroedel/dmarc-monitor/releases/latest/download/dmarc-monitor-linux-amd64" -o "$B" && chmod +x "$B"; }; "$B" -cron >> "$D/cron.log" 2>&1 || echo "dmarc-monitor failed; see $D/cron.log"
```

That is the whole deployment. The first scheduled run fetches the binary and
keeps it current from then on.

### Starting it now instead of at the next scheduled hour

There is no binary to invoke yet — the crontab line is what downloads it — so
this is the same fetch, by hand:

```bash
D="$HOME/dmarc-monitor"; B="$D/dmarc-monitor"; mkdir -p "$D"; \
  curl -fsSL "https://github.com/jroedel/dmarc-monitor/releases/latest/download/dmarc-monitor-linux-amd64" \
  -o "$B" && chmod +x "$B" && "$B" -version
```

After that the usual checks work, and the first real run wants `-include-seen`
once, to sweep up reports already sitting read in the mailbox:

```bash
~/dmarc-monitor/dmarc-monitor -check
~/dmarc-monitor/dmarc-monitor -once -dry-run -include-seen
~/dmarc-monitor/dmarc-monitor -once -include-seen
```

### One directory holds the installation

```
~/dmarc-monitor/
  credentials.env   the mailbox and relay passwords   (you write this)
  dmarc-monitor     the binary                        (downloads itself)
  state.json        what it remembers between runs
  run.lock          held while a run is going
  cron.log          what the last runs did
```

So an install can be listed, copied, backed up or deleted in one go, and none
of it is anywhere else. The credentials and state files are found beside the
binary; a file left at the older `~/.local/share` or `~/.local/state` location
is still honoured, so an installation predating this keeps working — nothing is
moved automatically, because relocating somebody's credentials unasked is not a
thing a monitoring program should do.

### The schedule

08:00 and 20:00 US Central, on a server in any timezone. Reports arrive once a
day, so this sees one within twelve hours; a run takes about a second.

### Why it wakes hourly and throws most of it away

**Debian and Ubuntu cron cannot schedule in another timezone.** `crontab(5)`
says so under LIMITATIONS: it "does not support per-user timezones... even if a
user specifies the `TZ` environment variable in his crontab this will affect
only the commands executed in the crontab, not the execution of the crontab
tasks themselves". A `CRON_TZ=America/Chicago` line *looks* like it works, is
silently ignored for scheduling, and leaves a German server firing seven hours
out. The hourly guard is the workaround that same man page recommends.

Asking Chicago what time it is, rather than computing an offset from Berlin, is
also what survives daylight saving. The two zones switch on different dates, so
for **28 days a year the gap is six hours instead of seven** — a crontab with
German clock times hardcoded is an hour wrong every March and October. The guard
fires exactly twice a day through all four transitions, with no skipped or
duplicated runs.

`dmarc-monitor -check` prints what the schedule means in local time:

```
Local time here is 12:32 CEST; in America/Chicago it is 05:32 CDT.
deploy/crontab.example runs at 08:00 and 20:00 America/Chicago,
which is 15:00 CEST and 03:00 CEST here today.
```

It also fails loudly if the machine cannot resolve `America/Chicago` — without
tzdata, the shell's `date` answers in UTC without complaining, which would move
every run by two hours in winter and three in summer.

`-cron` is three things in order: take a lock, so a long run is never joined by
the next one; check for a newer release and install it; run one cycle and exit.

**The one thing that cannot be bootstrapped is the credentials file** — it holds
the mailbox password. The first scheduled run writes the annotated template to
`~/.local/share/dmarc-monitor/credentials.env` and exits non-zero, so `MAILTO`
tells you it is waiting. Fill it in, and the next run works. That is the only
time anyone needs to log in to the server.

Four details in that line are load-bearing, and each is a real failure:

- **The backslash in `date +\%H` is required**, and there is no other `%` in the
  line. cron turns an unescaped percent sign into a newline, which would truncate
  the command mid-guard; that is also why the directory is a separate variable
  rather than `"${B%/*}"`.
- **`mkdir` before the redirect.** A redirect into a directory that does not
  exist fails the entry before anything runs.
- **`HOME` is left alone.** Both the credentials and the state file are found
  relative to it; a crontab that overrides `HOME` sends the program looking for
  its password somewhere it is not.
- **The trailing `|| echo` is what makes `MAILTO` work.** cron mails whatever a
  job writes, so a job that redirects everything into a log mails nothing —
  including on the day it fails. Detail goes to the log, one line goes to mail,
  and only on failure.

On arm64, change the asset name to `dmarc-monitor-linux-arm64`.

`-watch` still exists if you would rather run it resident, polling on
`POLL_INTERVAL`.

## Releasing

Servers install published releases and nothing else — never a branch, never a
commit on main — so shipping is a deliberate act:

```bash
make release V=v0.1.0     # tags, pushes, and the workflow does the rest
gh run watch
```

`.github/workflows/release.yml` re-runs the full gate, builds linux/amd64,
linux/arm64 and darwin/arm64 with the version stamped in, generates
`checksums.txt` from the very files it uploads, and publishes them.

Each server mails you when it takes one — subject `[dmarc] updated to v0.2.0 on
<host>`, naming the versions, the binary it replaced and the release page. That
is how an unattended deployment is verified: the mail arriving *is* the proof
the pipeline reached the machine, without logging in to check. It is sent only
when a build actually lands, before the cycle that follows, so it arrives even
if that cycle then fails. `ALERT_ON_UPDATE=false` turns it off once it stops
being interesting.

Each server picks the release up at its next scheduled run. `foundation/selfupdate`
verifies the download against `checksums.txt` before replacing anything, and a
mismatch aborts without touching the working binary — the monitor carries on
with the build it has, which still sends alerts. Prereleases and drafts are
ignored.

The new binary is put in place with a rename, so the running process keeps its
own inode and finishes the cycle it is in. The update takes effect at the next
run; nothing is ever swapped out mid-cycle.

That auto-update is also the sharpest edge in this repository: anything
published under a `v*` tag runs on the server as the user holding the mailbox
password. The checksums make the *transport* trustworthy, not the *contents* —
what protects the contents is that cutting a tag is manual and CI has to pass
first.

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
foundation/apppath        where an installation's files live
foundation/selfupdate     installing published releases, checksum-verified
foundation/lockfile       one run at a time
foundation/logger         slog setup
deploy/crontab.example    the entire deployment
```

Business domains never import each other; `app/monitor` composes them, and
`app/monitor/convert.go` holds every crossing. Primitives live at the edges,
strong types only in the Business layer. See `AGENTS.md`.

## The Go toolchain

`go.mod` pins `go 1.26.6` rather than a bare `go 1.26`, and the pin is
load-bearing. Five standard-library advisories fixed in 1.26.6 are reachable
from this program — it parses XML written by strangers and speaks TLS to two
servers — so `make test` fails its `vuln-check` on anything older.

With the default `GOTOOLCHAIN=auto`, the `go` command downloads that exact
toolchain the first time it builds here and caches it under `$GOPATH`. No root,
and no dependence on whatever the distribution ships: Ubuntu's
`longsleep/golang-backports` PPA was still on 1.26.5 when this was written, so
`apt upgrade` would not have been enough.

The build host is the only machine that needs Go at all. Cron runs a compiled
static binary, so the toolchain version is a build-time property that travels
baked into the artefact.

## Development

```bash
make test           # unit tests + lint + govulncheck
make test-unit      # offline
make lint           # go vet + gofmt check
```
