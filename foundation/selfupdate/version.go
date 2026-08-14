package selfupdate

import (
	"strconv"
	"strings"
)

// DevVersion is what an unstamped local build reports. A binary built with
// `go build` rather than by the release pipeline carries this, and it is
// treated as older than any published release — a server accidentally running
// a hand-built binary should adopt the real one at the next run.
const DevVersion = "dev"

// newer reports whether the release tag is a later version than what is
// running.
//
// Comparison is numeric, field by field, because string ordering gets v1.10.0
// wrong against v1.9.0 — and getting that wrong means an update that installs
// itself in a loop, twice a day, forever.
//
// Anything that does not parse as MAJOR.MINOR.PATCH is refused rather than
// guessed at. The cost of refusing is a missed update, announced in the log;
// the cost of guessing is a binary replaced on a whim.
func newer(tag, current string) bool {
	if tag == "" {
		return false
	}

	release, ok := parseVersion(tag)
	if !ok {
		return false
	}

	if current == "" || current == DevVersion {
		return true
	}

	running, ok := parseVersion(current)
	if !ok {
		return false
	}

	for i := range release {
		if release[i] != running[i] {
			return release[i] > running[i]
		}
	}

	// Identical numbers: a prerelease suffix on the running build (v1.2.0-rc1)
	// makes the plain tag (v1.2.0) the later one, per semver.
	return prerelease(current) != "" && prerelease(tag) == ""
}

// parseVersion reads a leading "v", three dot-separated numbers, and ignores
// any -prerelease or +build suffix.
func parseVersion(s string) ([3]int, bool) {
	var out [3]int

	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")

	if cut, _, found := strings.Cut(s, "+"); found {
		s = cut
	}
	if cut, _, found := strings.Cut(s, "-"); found {
		s = cut
	}

	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, false
	}

	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return out, false
		}

		out[i] = n
	}

	return out, true
}

// prerelease returns the -suffix of a version, or "".
func prerelease(s string) string {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")

	if cut, _, found := strings.Cut(s, "+"); found {
		s = cut
	}

	_, pre, _ := strings.Cut(s, "-")

	return pre
}
