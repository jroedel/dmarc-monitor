#!/usr/bin/env bash
#
# Put dmarc-monitor on the konsoleH account.
#
# The target is shared hosting with no root and no systemd: ssh, cron and a
# static binary are what everything here is built out of. Adapted from
# stewards' deploy.sh, and much smaller, because this is not a server: there is
# no process to stop, no port to health-check and no database to back up. The
# binary runs from cron twice a day for about a second, so a deploy is an
# atomic rename and a crontab line.
#
# Run from CI on every push to main, and by a person through `make deploy` and
# the `make prod-*` targets. Never by an agent (AGENTS.md; .claude/settings.json
# denies it).
#
# There is no separate one-time install. Everything an install would do -- the
# directory, the binary, the crontab line -- is idempotent and runs on every
# deploy, so the first push to main is the install. What it cannot create is
# credentials.env, which a person puts there with `make deploy-send-secrets`.
#
# The repository is public, and so are its Actions logs. Nothing here prints
# what the binary says about the mailbox: -check's output names the alert
# recipients, and its errors can name the mailbox account. In CI a failure says
# which make target shows the detail, on a person's own terminal.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS_ENV="${SECRETS_ENV:-$REPO_DIR/secrets.env}"

APP=dmarc-monitor
CRON_MARKER="# $APP"

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m !!\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[32m  ok\033[0m %s\n' "$*"; }
bad()  { printf '\033[31m   X\033[0m %s\n' "$*"; }
die()  { printf '\033[31mX\033[0m %s\n' "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || die "$1 is required but is not installed"; }

# shellcheck source=../scripts/env.sh
. "$REPO_DIR/scripts/env.sh"

# ------------------------------------------------------------------ config

# In CI the values arrive as environment variables; on a person's machine they
# come from secrets.env. Same names either way. The file is read only when it
# exists, and a runner never has one.
load_config() {
	[ ! -f "$SECRETS_ENV" ] || parse_env "$SECRETS_ENV"

	: "${DEPLOY_SSH_HOST:?DEPLOY_SSH_HOST is not set. On your machine it belongs in secrets.env; in CI it is a repository secret}"
	: "${DEPLOY_SSH_USER:?DEPLOY_SSH_USER is not set}"
	: "${APP_DIR:?APP_DIR is not set. It belongs in secrets.env and, for CI, in the GitHub variables: make deploy-send-secrets}"

	DEPLOY_SSH_PORT="${DEPLOY_SSH_PORT:-22}"
	KEEP_BACKUPS="${KEEP_BACKUPS:-14}"

	if ! [[ "$KEEP_BACKUPS" =~ ^[0-9]+$ ]] || [ "$KEEP_BACKUPS" -lt 1 ]; then
		die "KEEP_BACKUPS is \"$KEEP_BACKUPS\"; it must be a whole number of at least 1"
	fi

	# credentials.env lives here. Inside any site's docroot, Apache would
	# serve the mailbox password; and an absolute path or a .. is a deploy
	# writing somewhere other than the one directory it owns.
	case "$APP_DIR" in
	/*|*..*) die "APP_DIR ($APP_DIR) must be a plain path relative to the account's home, such as dmarc-monitor" ;;
	public_html|public_html/*|*/public_html|*/public_html/*)
		die "APP_DIR ($APP_DIR) is inside public_html, where Apache could serve credentials.env. Put it beside public_html, such as ~/dmarc-monitor"
		;;
	esac

	Q_DIR="$(printf '%q' "$APP_DIR")"
}

# ssh_setup decodes the key and the pinned host key into a directory removed
# on exit. There is no unpinned fallback: a deploy that trusts whatever answers
# on port 22 is a deploy that can be handed somebody else's shell.
SSH_TMP="$(mktemp -d)"
chmod 700 "$SSH_TMP"
trap 'rm -rf "$SSH_TMP"' EXIT
SSH_OPTS=()

ssh_setup() {
	require ssh

	printf '%s' "${DEPLOY_SSH_KEY_B64:?DEPLOY_SSH_KEY_B64 is not set. Run: make deploy-keygen}" \
		| base64 -d > "$SSH_TMP/key" 2>/dev/null \
		|| die "DEPLOY_SSH_KEY_B64 is not valid base64. Run: make deploy-status"
	chmod 600 "$SSH_TMP/key"

	grep -q 'BEGIN OPENSSH PRIVATE KEY' "$SSH_TMP/key" \
		|| die "DEPLOY_SSH_KEY_B64 decodes to something that is not an ssh private key"

	printf '%s' "${DEPLOY_KNOWN_HOSTS_B64:?DEPLOY_KNOWN_HOSTS_B64 is not set; a deploy must be pinned. Run: make deploy-known-hosts}" \
		| base64 -d > "$SSH_TMP/known_hosts" 2>/dev/null \
		|| die "DEPLOY_KNOWN_HOSTS_B64 is not valid base64. Run: make deploy-known-hosts"

	SSH_OPTS=(
		-i "$SSH_TMP/key"
		-o "UserKnownHostsFile=$SSH_TMP/known_hosts"
		-o StrictHostKeyChecking=yes
		-o ConnectTimeout=15
		-o BatchMode=yes
	)
}

remote()        { ssh "${SSH_OPTS[@]}" -p "$DEPLOY_SSH_PORT" "$DEPLOY_SSH_USER@$DEPLOY_SSH_HOST" "$@"; }
remote_in_app() { remote "cd $Q_DIR || exit 1
$1"; }
push_file()     { scp -q "${SSH_OPTS[@]}" -P "$DEPLOY_SSH_PORT" "$1" "$DEPLOY_SSH_USER@$DEPLOY_SSH_HOST:$2"; }

# ------------------------------------------------------------------ guards

# ensure_main stops a person deploying a branch or a dirty tree by accident.
# CI sets SKIP_GIT_CHECK: a runner's checkout is a detached HEAD, and its
# trigger already is "a commit on main".
ensure_main() {
	[ -z "${SKIP_GIT_CHECK:-}" ] || return 0
	[ -z "${DEPLOY_ALLOW_BRANCH:-}" ] || return 0

	local branch; branch="$(git -C "$REPO_DIR" rev-parse --abbrev-ref HEAD)"
	[ "$branch" = "main" ] || die "on branch $branch; deploys come from main. Set DEPLOY_ALLOW_BRANCH=1 to override"

	if ! git -C "$REPO_DIR" diff --quiet || ! git -C "$REPO_DIR" diff --cached --quiet; then
		die "the working tree has uncommitted changes; what would be deployed is not what is committed"
	fi
}

# superseded reports whether main has moved past the commit being deployed.
#
# Merging three pull requests in a minute queues three deploys; the workflow's
# concurrency group runs them one at a time, and each that finds a newer commit
# on main stops before touching anything and leaves the work to the last.
#
# Failing open is deliberate: if the tip cannot be read, deploy. A deploy that
# silently does nothing because it could not reach GitHub is worse than one
# extra rename.
superseded() {
	[ -z "${DEPLOY_ALLOW_BRANCH:-}" ] || return 1

	local mine tip
	mine="$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null)" || return 1
	tip="$(git -C "$REPO_DIR" ls-remote origin refs/heads/main 2>/dev/null | cut -f1)" || return 1

	if [ -z "$mine" ] || [ -z "$tip" ]; then return 1; fi
	[ "$mine" != "$tip" ]
}

# ------------------------------------------------------------------ cron

# cron_line is the one crontab entry this project owns.
#
# Runs at 08:00 and 20:00 US Central, on a server in any timezone. Cron wakes
# hourly and the guard throws away the 22 wakeups that are not the right hour
# in Chicago. That looks roundabout, and is the only way that works here:
#
#   Debian and Ubuntu cron CANNOT schedule in another timezone. Its crontab(5)
#   says so under LIMITATIONS: a TZ or CRON_TZ line affects the commands, not
#   when they run. It looks like it works, is silently ignored for
#   scheduling, and leaves the job firing at German local time, seven hours
#   out. The hourly guard is the workaround that same man page recommends.
#
# Asking Chicago what time it is, rather than computing an offset from Berlin,
# keeps this right across daylight saving: the two zones change on different
# dates, so for 28 days a year the gap is six hours, not seven.
#
# The other traps, in the order they bite:
#
# * The backslash in `date +\%H` is required. cron turns an unescaped percent
#   sign into a newline, which would cut the command off mid-guard.
#
# * The trailing `|| echo` is what makes the crontab's MAILTO work. cron mails
#   whatever a job prints, so a job that redirects everything into a log mails
#   nothing -- including on the day it fails. Detail to the log, one line to
#   stdout on failure: a quiet mailbox on a normal day and a mail on a bad one.
#
# * The marker comment at the end is how this line is found again, and the
#   only way: the crontab is shared with stewards and mass-intentions, and each
#   project removes only its own marked lines before writing them back.
#
# The binary takes a lock, so a run that overruns is never joined by the next,
# and a hand-run copy cannot collide with a scheduled one.
cron_line() {
	printf '%s\n' "0 * * * * H=\"\$(TZ=America/Chicago date +\\%H)\"; [ \"\$H\" = 08 ] || [ \"\$H\" = 20 ] || exit 0; cd $Q_DIR && ./$APP -cron >> cron.log 2>&1 || echo \"$APP failed; see $APP_DIR/cron.log\" $CRON_MARKER"
}

# cron_rewrite reads a crontab on stdin and prints it with this project's line
# in place: every line carrying our marker goes, as does the self-updating line
# from before deploys came over ssh -- found by the release download URL that
# only it ever contained -- and the current line is appended. Everything else
# passes through untouched, MAILTO and the other projects' lines included.
#
# A filter on stdin rather than a remote command so that scripts/deploy-test.sh
# can hold it against a crontab with other projects' lines in it, without a
# server.
cron_rewrite() {
	grep -v -e " $CRON_MARKER\$" -e "releases/latest/download/$APP-" || true
	cron_line
}

install_cron() {
	local current
	current="$(remote "crontab -l 2>/dev/null || true")"

	printf '%s\n' "$current" | cron_rewrite | remote "crontab -"

	ok "the schedule is installed"
}

# ------------------------------------------------------------------ deploy

# backup_state copies state.json aside before a swap. It is what stops a run
# re-alerting on every report it has already seen, and the one file on the
# server that is neither in git nor in secrets.env. A new build that misread it
# would rewrite it at the end of its first cycle; a copy from before is what
# makes that recoverable. Named by timestamp, newest kept, oldest pruned.
backup_state() {
	local stamp; stamp="$(date -u +%Y%m%dT%H%M%SZ)"

	remote_in_app "if [ -f state.json ]; then
		mkdir -p backups && chmod 700 backups
		cp -p state.json backups/state-$stamp.json
		ls -1 backups/state-*.json 2>/dev/null | sort -r | tail -n +$((KEEP_BACKUPS + 1)) | while read -r old; do rm -f \"\$old\"; done
		echo 'state.json backed up, keeping $KEEP_BACKUPS'
	else
		echo 'no state.json yet, so nothing to back up'
	fi"
}

cmd_deploy() {
	load_config
	ensure_main
	ssh_setup

	local version commit
	version="$(git -C "$REPO_DIR" describe --tags --always --dirty)"
	commit="$(git -C "$REPO_DIR" rev-parse HEAD)"

	log "building $version"
	make -C "$REPO_DIR" --no-print-directory release-build VERSION="$version" COMMIT="$commit"

	log "uploading"
	remote "mkdir -p $Q_DIR && chmod 700 $Q_DIR"
	push_file "$REPO_DIR/$APP-linux-amd64" "$APP_DIR/$APP.new"
	remote_in_app "chmod 700 $APP.new"

	# Pre-flight: the NEW binary, on the server, against the LIVE credentials,
	# while the old one is still in place. It proves the build runs on that
	# machine, that it accepts the credentials file -- the binary refuses keys
	# it does not know, so a key a newer build dropped would stop every run --
	# and that the mailbox and the relay both let it in. -check sends nothing.
	#
	# Its output goes nowhere: the Actions log is public, and -check names the
	# alert recipients and, on failure, the mailbox account.
	log "pre-flight: does the new build run there, and log in with the live credentials?"
	remote_in_app "./$APP.new -version" || die "the new build does not run on the server. Nothing was changed"

	if ! remote_in_app "./$APP.new -check >/dev/null 2>&1"; then
		remote_in_app "rm -f $APP.new" || true
		die "the new build cannot log in with the credentials on the server. Nothing was changed. From your machine, 'make prod-check' shows why; if credentials.env is missing or stale, 'make deploy-send-secrets' installs it"
	fi
	ok "it does"

	# The last moment at which doing nothing is free: built, uploaded and
	# pre-flighted, and nothing on the server touched yet.
	if superseded; then
		log "a newer commit is already on main; its deploy follows this one"
		remote_in_app "rm -f $APP.new" || true
		log "stopping here. Nothing on the server was changed"
		return 0
	fi

	log "state"
	backup_state

	# mv rather than cp over the old file: overwriting a binary that is
	# executing gives ETXTBSY, and a rename is atomic. A cron run already going
	# keeps its own inode and finishes on the old build; the next one starts on
	# the new. So there is no lock to take and no window to close.
	log "swapping"
	remote_in_app "set -e
[ ! -f $APP ] || cp -p $APP $APP.prev
mv $APP.new $APP
printf '%s %s\n' '$commit' '$version' > deployed-commit.txt"

	# The crontab after the binary, so the line never names a file that is not
	# there yet.
	log "schedule"
	install_cron

	rm -f "$REPO_DIR/$APP-linux-amd64"

	log "deployed $version. The next scheduled run mails the deploy notice (08:00 or 20:00 Chicago); make prod-dry-run shows what it would do now"
}

# cmd_rollback puts the previous binary back. There is no health check to roll
# back on automatically -- the pre-flight is the gate -- so this is for the
# person who reads the deploy notice, or the cron failure mail, and wants the
# last build back while a fix is made. It swaps, so running it twice is a
# roll-forward.
cmd_rollback() {
	load_config
	ssh_setup

	remote_in_app "set -e
[ -f $APP.prev ] || { echo 'there is no previous binary to roll back to' >&2; exit 1; }
mv $APP $APP.rollback && mv $APP.prev $APP && mv $APP.rollback $APP.prev
printf '%s\n' 'rolled back by hand' > deployed-commit.txt
./$APP -version"

	ok "rolled back. A push to main deploys again; make prod-rollback again undoes this"
}

# ------------------------------------------------------------------ the server, for a person

# Everything below runs the binary on the server and prints what it says, which
# is the mailbox's business. They are for a person at a terminal, never for CI.

cmd_status() {
	load_config
	ssh_setup

	log "what is installed"
	remote_in_app "./$APP -version 2>/dev/null || echo '(no binary)'"
	remote_in_app "cat deployed-commit.txt 2>/dev/null || echo '(nothing deployed yet)'"

	log "the schedule"
	remote "crontab -l 2>/dev/null | grep -e '^MAILTO=' -e ' $CRON_MARKER\$' -e 'releases/latest/download/$APP-' || echo '(no crontab line)'"

	log "the last runs"
	remote_in_app "grep -E -o '\"(last_run|running_version)\": *\"[^\"]*\"' state.json 2>/dev/null || echo '(no state yet)'"
	remote_in_app "ls -1 backups/state-*.json 2>/dev/null | sort -r | head -3 || true"
	remote_in_app "tail -n 10 cron.log 2>/dev/null || echo '(no cron.log yet)'"
}

cmd_logs()       { load_config; ssh_setup; remote_in_app "tail -n $(printf '%q' "${1:-80}") cron.log"; }
cmd_check()      { load_config; ssh_setup; remote_in_app "./$APP -check"; }
cmd_dry_run()    { load_config; ssh_setup; remote_in_app "./$APP -once -dry-run"; }
cmd_test_alert() { load_config; ssh_setup; remote_in_app "./$APP -test-alert"; }

usage() {
	cat <<-USAGE
		usage: deploy/deploy.sh <command>

		  deploy        build, upload, pre-flight, back up state, swap, install the crontab line
		  rollback      put the previous binary back (twice is a roll-forward)
		  status        what is installed and scheduled, and the last runs
		  logs [n]      the last n lines of cron.log (80)
		  check         run -check on the server: both ends reachable; sends nothing
		  dry-run       run one cycle on the server, print the alert; sends and changes nothing
		  test-alert    send one real test message from the server
		  cron-rewrite  filter a crontab on stdin as a deploy would (for tests)
	USAGE
}

case "${1:-}" in
deploy)       shift; cmd_deploy "$@" ;;
rollback)     shift; cmd_rollback "$@" ;;
status)       shift; cmd_status "$@" ;;
logs)         shift; cmd_logs "$@" ;;
check)        shift; cmd_check "$@" ;;
dry-run)      shift; cmd_dry_run "$@" ;;
test-alert)   shift; cmd_test_alert "$@" ;;
cron-rewrite) shift; Q_DIR="$(printf '%q' "${APP_DIR:?APP_DIR is not set}")"; cron_rewrite ;;
*)            usage; exit 2 ;;
esac
