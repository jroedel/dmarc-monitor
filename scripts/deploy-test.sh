#!/usr/bin/env bash
#
# Tests for the parts of deploy/deploy.sh that edit a crontab it shares with
# other projects and swap the binary under the run lock, and for the crontab
# line itself. No server: the rewrite is a filter on stdin, the line is run
# here under sh with date and the binary stubbed, and the swap script is run in
# a scratch directory against a lock held with flock.
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

echo "the swap, run"
# The script a deploy runs on the server, run here under sh in an app
# directory with a state file, the live binary and the uploaded one, against
# run.lock free, held for a moment by a cycle, and held by a stuck one.
command -v flock >/dev/null || { echo "  flock (util-linux) is needed for these"; exit 1; }

swap() { LOCK_WAIT="$1" KEEP_BACKUPS=14 "$DEPLOY" swap-script abc123 v9.9.9; }

app_dir() {
	local dir="$TMP/app-$1"
	mkdir -p "$dir"
	echo '{"seen":1}' > "$dir/state.json"
	echo old > "$dir/dmarc-monitor"
	echo new > "$dir/dmarc-monitor.new"
	printf '%s' "$dir"
}

dir="$(app_dir free)"
if ( cd "$dir" && swap 1 | sh ) > "$dir/out" 2>&1; then pass "with the lock free it swaps"; else fail "with the lock free it failed: $(cat "$dir/out")"; fi
if [ "$(cat "$dir/dmarc-monitor")" = new ] && [ "$(cat "$dir/dmarc-monitor.prev")" = old ] && [ ! -e "$dir/dmarc-monitor.new" ]; then
	pass "the new build is live and the old one kept as .prev"
else
	fail "the binaries are not where a swap leaves them: $(ls "$dir")"
fi
if cmp -s "$dir/state.json" "$dir"/backups/state-*.json; then pass "state.json is backed up"; else fail "no backup of state.json: $(ls "$dir")"; fi
if grep -qx 'abc123 v9.9.9' "$dir/deployed-commit.txt"; then pass "deployed-commit.txt names the build"; else fail "deployed-commit.txt: $(cat "$dir/deployed-commit.txt")"; fi

# A cycle in progress: the lock is let go a second in, and the deploy waits
# for it rather than swapping underneath. The cycle notes which build is in
# place as it finishes, which must still be the old one.
dir="$(app_dir busy)"
# shellcheck disable=SC2016 # $1 is the inner shell's, not this one's
flock "$dir/run.lock" sh -c 'sleep 1; cat "$1/dmarc-monitor" > "$1/seen-by-cycle"' sh "$dir" &
holder=$!
sleep 0.2
if ( cd "$dir" && swap 10 | sh ) > "$dir/out" 2>&1 && [ "$(cat "$dir/dmarc-monitor")" = new ]; then
	pass "it swaps once a cycle in progress is done"
else
	fail "it did not swap after the cycle finished: $(cat "$dir/out")"
fi
wait "$holder"
if [ "$(cat "$dir/seen-by-cycle")" = old ]; then pass "and not underneath it"; else fail "it swapped while the cycle held the lock"; fi

# A stuck cycle: it exits 75, and nothing has changed.
dir="$(app_dir stuck)"
flock "$dir/run.lock" sleep 5 &
holder=$!
sleep 0.2
status=0
( cd "$dir" && swap 1 | sh ) > "$dir/out" 2>&1 || status=$?
if [ "$status" = 75 ]; then pass "a stuck cycle makes it exit 75"; else fail "a stuck cycle made it exit $status: $(cat "$dir/out")"; fi
if [ "$(cat "$dir/dmarc-monitor")" = old ] && [ -e "$dir/dmarc-monitor.new" ] && [ ! -e "$dir/backups" ] && [ ! -e "$dir/deployed-commit.txt" ]; then
	pass "and changes nothing"
else
	fail "a stuck cycle still changed things: $(ls "$dir")"
fi
kill "$holder" 2>/dev/null || true
wait "$holder" 2>/dev/null || true

echo
[ "$FAILED" -eq 0 ] || { echo "$FAILED failure(s)"; exit 1; }
echo "all passed"
