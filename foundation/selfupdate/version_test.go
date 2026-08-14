package selfupdate

import "testing"

func TestNewer(t *testing.T) {
	tests := []struct {
		name    string
		tag     string
		current string
		want    bool
	}{
		{"patch bump", "v1.2.4", "v1.2.3", true},
		{"minor bump", "v1.3.0", "v1.2.9", true},
		{"major bump", "v2.0.0", "v1.99.99", true},
		{"same", "v1.2.3", "v1.2.3", false},
		{"older", "v1.2.2", "v1.2.3", false},
		{"older minor", "v1.1.9", "v1.2.0", false},

		// String comparison gets this one wrong, and getting it wrong means a
		// server reinstalling the same binary twice a day forever.
		{"double digits", "v1.10.0", "v1.9.0", true},
		{"double digits reversed", "v1.9.0", "v1.10.0", false},
		{"double digit patch", "v1.0.10", "v1.0.9", true},

		{"no v prefix", "1.2.4", "1.2.3", true},
		{"mixed prefix", "v1.2.4", "1.2.3", true},

		// An unstamped local build should adopt a real release.
		{"dev adopts a release", "v1.0.0", "dev", true},
		{"empty adopts a release", "v1.0.0", "", true},

		// Semver: a release outranks the prerelease of the same version.
		{"release beats rc", "v1.2.0", "v1.2.0-rc1", true},
		{"rc does not beat release", "v1.2.0-rc1", "v1.2.0", false},

		// Anything unparsable is refused rather than guessed at.
		{"garbage tag", "latest", "v1.2.3", false},
		{"empty tag", "", "v1.2.3", false},
		{"two part tag", "v1.2", "v1.1.0", false},
		{"garbage current", "v1.2.3", "nightly", false},
		{"negative", "v1.-2.0", "v1.1.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newer(tt.tag, tt.current); got != tt.want {
				t.Errorf("newer(%q, %q) = %v, want %v", tt.tag, tt.current, got, tt.want)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	tests := map[string]struct {
		want [3]int
		ok   bool
	}{
		"v1.2.3":        {[3]int{1, 2, 3}, true},
		"1.2.3":         {[3]int{1, 2, 3}, true},
		"v1.2.3-rc1":    {[3]int{1, 2, 3}, true},
		"v1.2.3+build7": {[3]int{1, 2, 3}, true},
		"v10.20.30":     {[3]int{10, 20, 30}, true},
		"v1.2":          {[3]int{}, false},
		"v1.2.3.4":      {[3]int{}, false},
		"dev":           {[3]int{}, false},
		"":              {[3]int{}, false},
	}

	for input, tt := range tests {
		t.Run(input, func(t *testing.T) {
			got, ok := parseVersion(input)
			if ok != tt.ok {
				t.Fatalf("parseVersion(%q) ok = %v, want %v", input, ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Errorf("parseVersion(%q) = %v, want %v", input, got, tt.want)
			}
		})
	}
}
