# shellcheck shell=bash
#
# The one parser for secrets.env, sourced by scripts/secrets and
# deploy/deploy.sh. Copied from stewards, which has the same file for the same
# reason: mass-intentions had two parsers, and the carriage-return and
# trailing-space fix went into one of them.

# parse_env reads a secrets.env-style file by parsing it rather than sourcing it.
#
# Sourcing would execute whatever is in the file, and a credentials file that
# runs commands is a credentials file that can be made to run somebody else's.
parse_env() {
	# A quoted value is taken exactly as written between its quotes. An
	# unquoted one loses what nobody means to be part of it: a trailing
	# comment after whitespace, and whitespace at either end.
	#
	# That second rule is not tidiness. The first version kept everything
	# after the "=", so KEEP_BACKUPS=14 with a space after it was sent to
	# GitHub as "14 ", GitHub stored "14", and the read-back reported a
	# mismatch nobody could see -- stopping deploy-send-secrets before it
	# wrote config.toml. Every key GitHub holds is compared against this
	# parse, so the parse has to agree with what a person sees in the file.
	local dq="^\"(.*)\"[[:space:]]*(#.*)?$"
	local sq="^'(.*)'[[:space:]]*(#.*)?$"

	local line key value
	while IFS= read -r line || [ -n "$line" ]; do
		# A file saved on Windows, or pasted out of a password manager that
		# writes CRLF, ends every line in a carriage return.
		line="${line%$'\r'}"

		case "$line" in ''|'#'*) continue ;; esac
		[[ "$line" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] || continue

		key="${BASH_REMATCH[1]}"
		value="${BASH_REMATCH[2]}"

		if [[ "$value" =~ $dq ]] || [[ "$value" =~ $sq ]]; then
			value="${BASH_REMATCH[1]}"
		else
			value="${value%%[[:space:]]#*}"
			value="${value#"${value%%[![:space:]]*}"}"
			value="${value%"${value##*[![:space:]]}"}"
		fi

		printf -v "$key" '%s' "$value"
		export "${key?}"
	done < "$1"
}
