#!/usr/bin/env bash
#
# Tests for scripts/secrets: what it writes into credentials.env, and that the
# binary would read back exactly what secrets.env held. Fixtures only; nothing
# here reads the real secrets.env or reaches GitHub or the server.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS="$REPO_DIR/scripts/secrets"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

FAILED=0
pass() { printf '  ok %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILED=$((FAILED + 1)); }

expect_line() {
	local name="$1" file="$2" line="$3"
	if grep -qxF -- "$line" "$file"; then pass "$name"; else fail "$name: no line $line in $(cat "$file")"; fi
}

# A fixture with the values that have bitten before: a password with " #" in
# it (quoted in secrets.env, as an unquoted one ends at the " #" there exactly
# as it does in credentials.env), one with "#" and no space, which needs no
# quotes in either, one with a double quote,
# one with spaces at either end, a CRLF line, and a trailing comment after an
# unquoted value in secrets.env itself.
cat > "$TMP/secrets.env" <<'ENV'
APP_DIR=dmarc-monitor
IMAP_USERNAME=dmarc@example.org
IMAP_PASSWORD="hunter #2"
IMAP_MOVE_TO=hunter#2
SMTP_USERNAME=alerts@example.org
SMTP_PASSWORD=say "hi"
ALERT_FROM=dmarc@example.org
ALERT_TO=a@example.org, b@example.org   # two of them
ALERT_SUBJECT_PREFIX="  [dmarc]  "
ALERT_FLOOR=
DEV_IMAP_USERNAME=test@example.net
DEV_IMAP_PASSWORD=devpass
DEV_SMTP_USERNAME=test@example.net
DEV_SMTP_PASSWORD=devpass
DEV_ALERT_FROM=test@example.net
DEV_ALERT_TO=me@example.net
ENV
printf 'IMAP_HOST=mail.example.org\r\n' >> "$TMP/secrets.env"

echo "render production"
SECRETS_ENV="$TMP/secrets.env" "$SECRETS" render production > "$TMP/prod.env"

expect_line "a password with ' #' survives, quoted" "$TMP/prod.env" 'IMAP_PASSWORD="hunter #2"'
expect_line "a '#' with no space before it is part of the value" "$TMP/prod.env" 'IMAP_MOVE_TO="hunter#2"'
expect_line "a value with a double quote is single-quoted" "$TMP/prod.env" "SMTP_PASSWORD='say \"hi\"'"
expect_line "spaces inside quotes are kept" "$TMP/prod.env" 'ALERT_SUBJECT_PREFIX="  [dmarc]  "'
expect_line "a trailing comment in secrets.env is not part of the value" "$TMP/prod.env" 'ALERT_TO="a@example.org, b@example.org"'
expect_line "a CRLF line loses its carriage return" "$TMP/prod.env" 'IMAP_HOST="mail.example.org"'

if grep -q '^ALERT_FLOOR=' "$TMP/prod.env"; then fail "an empty key is written"; else pass "an empty key is left out, so the default applies"; fi
if grep -q 'DEV_\|test@example.net' "$TMP/prod.env"; then fail "the DEV_ group leaked into production"; else pass "nothing from DEV_ reaches production"; fi
if grep -q 'APP_DIR' "$TMP/prod.env"; then fail "a deploy key reached credentials.env"; else pass "only runtime keys are written"; fi

echo "render local"
SECRETS_ENV="$TMP/secrets.env" "$SECRETS" render local > "$TMP/local.env"

expect_line "DEV_ keys lose their prefix" "$TMP/local.env" 'IMAP_USERNAME="test@example.net"'
if grep -q 'example.org' "$TMP/local.env"; then fail "production values leaked into the local file"; else pass "nothing from production reaches the local file"; fi

echo "refusals"
cp "$TMP/secrets.env" "$TMP/both.env"
printf '%s\n' "SMTP_PASSWORD=it's \"both\"" >> "$TMP/both.env"
if SECRETS_ENV="$TMP/both.env" "$SECRETS" render production > /dev/null 2>&1; then
	fail "a value with both quote characters was written"
else
	pass "a value with both quote characters is refused rather than mangled"
fi

grep -v '^ALERT_TO=' "$TMP/secrets.env" > "$TMP/missing.env"
if SECRETS_ENV="$TMP/missing.env" "$SECRETS" render production > /dev/null 2>&1; then
	fail "rendered without ALERT_TO"
else
	pass "a missing required key is refused"
fi

grep -v '^SMTP_' "$TMP/secrets.env" > "$TMP/norelay.env"
if SECRETS_ENV="$TMP/norelay.env" "$SECRETS" render production > "$TMP/norelay.out" 2>&1; then
	pass "no relay credentials renders, for a relay on the server itself"
else
	fail "no relay credentials was refused: $(cat "$TMP/norelay.out")"
fi

grep -v '^SMTP_PASSWORD=' "$TMP/secrets.env" > "$TMP/halfrelay.env"
if SECRETS_ENV="$TMP/halfrelay.env" "$SECRETS" render production > /dev/null 2>&1; then
	fail "a relay username without its password was written"
else
	pass "a relay username without its password is refused, as the binary would"
fi

echo "local"
export XDG_DATA_HOME="$TMP/xdg"
mkdir -p "$XDG_DATA_HOME/dmarc-monitor"
printf 'IMAP_PASSWORD=written-by-hand\n' > "$XDG_DATA_HOME/dmarc-monitor/credentials.env"
chmod 600 "$XDG_DATA_HOME/dmarc-monitor/credentials.env"

SECRETS_ENV="$TMP/secrets.env" "$SECRETS" local > /dev/null 2>&1
written="$XDG_DATA_HOME/dmarc-monitor/credentials.env"

if [ "$(stat -c %a "$written")" = 600 ]; then pass "written 0600, which the binary insists on"; else fail "mode is $(stat -c %a "$written")"; fi
expect_line "written from DEV_" "$written" 'IMAP_PASSWORD="devpass"'
expect_line "the hand-written file is kept as .prev" "$written.prev" 'IMAP_PASSWORD=written-by-hand'

echo "the key list agrees with the binary"
# The binary refuses a key it does not know, so a key in RUNTIME_KEYS that is
# not in foundation/config/build.go stops every run; one in build.go and not
# here can never be set from secrets.env.
ours="$(sed -n '/^RUNTIME_KEYS=(/,/^)/p' "$SECRETS" | grep -o '[A-Z][A-Z0-9_]*' | grep -v RUNTIME_KEYS | sort)"
theirs="$(grep -o '^\s*"[A-Z][A-Z0-9_]*":\s*true' "$REPO_DIR/foundation/config/build.go" | grep -o '[A-Z][A-Z0-9_]*' | sort)"
if [ -n "$ours" ] && [ "$ours" = "$theirs" ]; then
	pass "RUNTIME_KEYS matches the binary's known keys"
else
	fail "RUNTIME_KEYS and build.go differ: $(diff <(echo "$ours") <(echo "$theirs") | grep '^[<>]' | tr '\n' ' ')"
fi

echo
[ "$FAILED" -eq 0 ] || { echo "$FAILED failure(s)"; exit 1; }
echo "all passed"
