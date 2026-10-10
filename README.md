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
./dmarc-monitor -test-alert    # sends one real message, so you can go find it
./dmarc-monitor -once -dry-run # full cycle, prints the alert, sends nothing
./dmarc-monitor -once          # for real
```

`-check` and `-test-alert` answer different questions. `-check` proves the relay
accepts a connection and a password; it sends nothing, so it can be run as often
as you like. `-test-alert` proves the rest of the trip — that a message rendered
by this program, with these headers, from this address, actually reaches a human
rather than a spam folder. It prints the `Message-ID` it sent, which is the
string to search a mail server's log for when the answer is no.

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

**A merge to main is a deploy.** `.github/workflows/deploy.yml` re-runs the
checks and then `deploy/deploy.sh deploy`, which, over ssh to the konsoleH
account:

1. builds a static linux/amd64 binary, stamped with `git describe` and the
   commit;
2. uploads it beside the live one;
3. **pre-flights it**: the new binary runs `-check` on the server against the
   live `credentials.env`, so a build that will not start there, will not
   accept the credentials, or cannot log in to the mailbox or the relay is a
   deploy that changes nothing;
4. stops if a newer commit reached main meanwhile (its own deploy follows);
5. backs up `state.json` (keeping `KEEP_BACKUPS`);
6. swaps the binary with a rename, keeping the old one as `dmarc-monitor.prev`
   — a cron run in progress finishes on its own inode, the next starts on the
   new build;
7. installs its crontab line, removing only its own marked line (and the
   self-updating line from before ssh deploys); the other projects' lines and
   `MAILTO` are left alone.

The first scheduled run of a new build mails **`[dmarc] deployed <version> on
<host>`**, naming both versions and linking the commit. That mail is the proof
the deploy reached the machine, from the machine's own side; it is sent once,
before the cycle, so it arrives even if that cycle then fails.
`ALERT_ON_UPDATE=false` in `secrets.env` turns it off.

Nothing about the mailbox is ever in GitHub. The repository and its Actions
logs are public, so CI holds only the ssh deploy key; the mailbox and relay
passwords reach the server from a person's machine.

### secrets.env

Every credential lives in one file, `secrets.env`, kept in Bitwarden and never
committed; `secrets.env.example` documents it. Its groups go to different
places: `DEPLOY_*` to GitHub secrets, `APP_*` to GitHub variables, the runtime
keys to the server's `credentials.env`, and `DEV_*` to this machine's. From a
person's machine:

```bash
make deploy-keygen          # mint the deploy key; install its public half on konsoleH
make deploy-known-hosts     # pin the server's host key
make deploy-send-secrets    # GitHub secrets + variables; credentials.env to the server
make deploy-status          # is everything in place? says what is not
make local-credentials      # the DEV_* group, for make run / make check
```

`deploy-send-secrets` writes `credentials.env` only if the binary on the server
accepts it and can log in with it (`-check`, which sends nothing), and keeps
the previous one as `credentials.env.prev`.

### On the server, from your machine

```bash
make prod-status            # what is installed and scheduled, and the last runs
make prod-logs N=200        # the tail of cron.log
make prod-check             # mailbox and relay reachable? sends nothing
make prod-dry-run           # one cycle, the alert printed; sends and changes nothing
make prod-test-alert        # ONE REAL test message, and its Message-ID
make prod-rollback          # the previous binary back (again to roll forward)
make deploy                 # deploy from here; the ordinary path is a merge
```

`-test-alert` is worth running once after the first deploy: a relay that
authenticates is not the same as a mailbox that receives, and a filtered alert
looks exactly like a quiet month.

### One directory holds the installation

```
~/dmarc-monitor/
  dmarc-monitor        the binary                         (deploy)
  dmarc-monitor.prev   the one before it                  (deploy)
  credentials.env      the mailbox and relay passwords    (make deploy-send-secrets)
  state.json           what it remembers between runs
  backups/             state.json, one per deploy
  deployed-commit.txt  the commit and version live
  run.lock             held while a run is going
  cron.log             what the last runs did
```

The credentials and state files are found beside the binary; a file left at the
older `~/.local/share` or `~/.local/state` location is still honoured, so an
installation predating this keeps working.

### The schedule

08:00 and 20:00 US Central, on a server in any timezone. Reports arrive once a
day, so this sees one within twelve hours; a run takes about a second.

**Debian and Ubuntu cron cannot schedule in another timezone.** `crontab(5)`
says so under LIMITATIONS: a `TZ` or `CRON_TZ` line affects the commands, not
when they run. It looks like it works, is silently ignored, and leaves a German
server firing seven hours out. So cron wakes hourly and the line asks Chicago
what time it is, throwing away the 22 wakeups that are not 08 or 20 there —
the workaround that same man page recommends. Asking Chicago, rather than
computing an offset from Berlin, is also what survives daylight saving: the two
zones switch on different dates, so for 28 days a year the gap is six hours
instead of seven.

`dmarc-monitor -check` prints what the schedule means in local time, and fails
loudly if the machine cannot resolve `America/Chicago` — without tzdata, the
shell's `date` answers in UTC without complaining. `make deploy-status` checks
the same on the server.

The line's other traps — the escaped `\%`, and the trailing `|| echo` that makes
`MAILTO` mail on a failure and only on a failure — are explained beside
`cron_line` in `deploy/deploy.sh`, and held by `scripts/deploy-test.sh`, which
runs the line under `sh` with `date` stubbed.

`-cron` takes a lock, so a long run is never joined by the next one, runs one
cycle, and exits. `-watch` still exists if you would rather run it resident,
polling on `POLL_INTERVAL`.

## Maintenance

- **Dependabot** opens one grouped pull request a week for Go modules and one
  for GitHub Actions (pinned by commit). `.github/workflows/dependabot-merge.yml`
  merges each once it is a day old with CI green, and dispatches the deploy;
  a failed deploy fails that run, which is emailed.
- **CI** runs weekly on main as well as on every change, because govulncheck's
  answer moves without a commit.
- **Agents** open pull requests and never touch production; see `AGENTS.md`.
  `.claude/settings.json` denies the `deploy*`/`prod-*` targets, the scripts
  behind them, ssh, and reading `secrets.env`.

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
cmd/dmarc-monitor      flags, wiring, the -check/-test-alert/-init-credentials paths
app/monitor            the cycle; the only package that knows all three domains
business/domain/report    reportbus  + stores/imapstore
business/domain/triage    triagebus  + stores/kronkllm
business/domain/alert     alertbus   + stores/smtpstore
business/types            domainname, authresult, disposition, severity, email
foundation/dmarcxml       RFC 7489 wire format, zip/gzip unwrapping
foundation/config         the credentials file
foundation/checkpoint     what carries over between runs
foundation/apppath        where an installation's files live
foundation/lockfile       one run at a time
foundation/logger         slog setup
deploy/deploy.sh          the deployment: ship, rollback, and prod-* for a person
scripts/secrets           secrets.env to GitHub, the server, and this machine
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
make test           # unit + shell tests + lint + govulncheck
make test-unit      # offline
make shell-test     # secrets rendering and the crontab rewrite, on fixtures
make lint           # go vet + gofmt check
make shellcheck     # the shell scripts (CI has shellcheck)
make release-build  # the static binary the server runs
```
