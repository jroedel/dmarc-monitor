#!/usr/bin/env bash
#
# Tests for the part of deploy/deploy.sh that edits a crontab it shares with
# other projects, and for the crontab line itself. No server: the rewrite is a
# filter on stdin, and the line is run here under sh with date and the binary
# stubbed.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY="$REPO_DIR/deploy/deploy.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

FAILED=0
pass() { printf '  ok %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }

rewrite() { APP_DIR=dmarc-monitor SECRETS_ENV=/nonexistent "$DEPLOY" cron-rewrite; }

# What the shared konsoleH crontab plausibly holds on the day of the first
# ssh deploy: the other projects' lines, a MAILTO, and the self-updating line
# this project's README used to tell people to paste.
cat > "$TMP/crontab" <<'CRON'
MAILTO=webmaster@example.org
@reboot cd stewards && ./supervise.sh start # stewards
*/5 * * * * cd stewards && ./supervise.sh watch # stewards
*/5 * * * * cd mass-intentions && ./supervise.sh start production
0 * * * * H="$(TZ=America/Chicago date +\%H)"; [ "$H" = 08 ] || [ "$H" = 20 ] || exit 0; D="$HOME/dmarc-monitor"; B="$D/dmarc-monitor"; mkdir -p "$D"; [ -x "$B" ] || { curl -fsSL "https://github.com/jroedel/dmarc-monitor/releases/latest/download/dmarc-monitor-linux-amd64" -o "$B" && chmod +x "$B"; }; "$B" -cron >> "$D/cron.log" 2>&1 || echo "dmarc-monitor failed; see $D/cron.log"
CRON

echo "the rewrite"
rewrite < "$TMP/crontab" > "$TMP/once"
rewrite < "$TMP/once" > "$TMP/twice"

for line in 'MAILTO=webmaster@example.org' '# stewards$' 'mass-intentions'; do
	if grep -q -- "$line" "$TMP/once"; then pass "keeps $line"; else fail "dropped $line"; fi
done

if grep -q 'releases/latest/download' "$TMP/once"; then fail "the self-updating line survived"; else pass "the self-updating line is gone"; fi

n="$(grep -c ' # dmarc-monitor$' "$TMP/once" || true)"
if [ "$n" = 1 ]; then pass "exactly one line is ours"; else fail "$n lines are ours"; fi

if cmp -s "$TMP/once" "$TMP/twice"; then pass "a second deploy changes nothing"; else fail "a second deploy changed the crontab: $(diff "$TMP/once" "$TMP/twice")"; fi

ours="$(grep ' # dmarc-monitor$' "$TMP/once")"

# cron turns an unescaped % into a newline. A bare one would cut the guard off.
if grep -q 'date +\\%H' <<<"$ours" && ! grep -q '[^\\]%[^H]' <<<"$ours"; then
	pass "the only percent sign is escaped for cron"
else
	fail "the line has an unescaped percent sign: $ours"
fi

echo "the line, run"
# Strip the five schedule fields and do what cron does with \%, then run the
# command under sh in a fake home: date stubbed to answer the hour asked for,
# the binary stubbed to succeed or fail.
command="$(cut -d' ' -f6- <<<"$ours" | sed 's/\\%/%/g')"

run_line() {
	local hour="$1" exit_code="$2" home="$TMP/home-$1-$2"
	mkdir -p "$home/dmarc-monitor" "$home/bin"

	printf '#!/bin/sh\necho %s\n' "$hour" > "$home/bin/date"
	printf '#!/bin/sh\necho "ran $*"\nexit %s\n' "$exit_code" > "$home/dmarc-monitor/dmarc-monitor"
	chmod +x "$home/bin/date" "$home/dmarc-monitor/dmarc-monitor"

	( cd "$home" && HOME="$home" PATH="$home/bin:/usr/bin:/bin" sh -c "$command" ) > "$home/stdout" 2>&1 || true
	printf '%s' "$home"
}

home="$(run_line 08 0)"
if grep -qx 'ran -cron' "$home/dmarc-monitor/cron.log" 2>/dev/null; then pass "at 08 Chicago it runs -cron into cron.log"; else fail "at 08 it did not run: $(cat "$home/stdout")"; fi
if [ ! -s "$home/stdout" ]; then pass "a good run prints nothing, so cron mails nothing"; else fail "a good run printed: $(cat "$home/stdout")"; fi

home="$(run_line 09 0)"
if [ ! -e "$home/dmarc-monitor/cron.log" ]; then pass "at 09 Chicago it does nothing"; else fail "at 09 it ran"; fi

home="$(run_line 20 1)"
if grep -q 'dmarc-monitor failed' "$home/stdout"; then pass "a failed run prints one line, so cron mails it"; else fail "a failed run was silent"; fi

echo
[ "$FAILED" -eq 0 ] || { echo "$FAILED failure(s)"; exit 1; }
echo "all passed"
