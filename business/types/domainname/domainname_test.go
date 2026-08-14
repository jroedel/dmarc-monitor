package domainname_test

import (
	"testing"

	"github.com/jroedel/dmarc-monitor/business/types/domainname"
)

func TestParseNormalises(t *testing.T) {
	tests := map[string]string{
		"plain":          "example.com",
		"uppercase":      "Example.COM",
		"trailing dot":   "example.com.",
		"surrounding ws": "  example.com  ",
		"subdomain":      "mail.example.com",
		"underscore":     "_dmarc.example.com",
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := domainname.Parse(input)
			if err != nil {
				t.Fatalf("Parse(%q): unexpected error: %v", input, err)
			}

			want := "example.com"
			if name == "subdomain" {
				want = "mail.example.com"
			}
			if name == "underscore" {
				want = "_dmarc.example.com"
			}

			if got.String() != want {
				t.Errorf("Parse(%q) = %q, want %q", input, got.String(), want)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	tests := map[string]string{
		"empty":           "",
		"dot only":        ".",
		"empty label":     "example..com",
		"leading hyphen":  "-example.com",
		"trailing hyphen": "example-.com",
		"illegal rune":    "exa mple.com",
		"label too long":  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com",
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := domainname.Parse(input); err == nil {
				t.Errorf("Parse(%q): want error, got none", input)
			}
		})
	}
}

func TestAligns(t *testing.T) {
	tests := []struct {
		name   string
		from   string
		policy string
		strict bool
		want   bool
	}{
		{"identical strict", "example.com", "example.com", true, true},
		{"identical relaxed", "example.com", "example.com", false, true},
		{"subdomain strict", "mail.example.com", "example.com", true, false},
		{"subdomain relaxed", "mail.example.com", "example.com", false, true},
		{"parent relaxed", "example.com", "mail.example.com", false, true},
		{"unrelated relaxed", "evil.com", "example.com", false, false},
		{"suffix trap", "notexample.com", "example.com", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			from := domainname.MustParse(tt.from)
			policy := domainname.MustParse(tt.policy)

			if got := from.Aligns(policy, tt.strict); got != tt.want {
				t.Errorf("%q.Aligns(%q, strict=%v) = %v, want %v", tt.from, tt.policy, tt.strict, got, tt.want)
			}
		})
	}
}

func TestZeroNeverAligns(t *testing.T) {
	var zero domainname.DomainName

	if zero.Aligns(domainname.MustParse("example.com"), false) {
		t.Error("the zero domain aligned with example.com")
	}
	if domainname.MustParse("example.com").Aligns(zero, false) {
		t.Error("example.com aligned with the zero domain")
	}
}
