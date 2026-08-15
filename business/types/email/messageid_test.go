package email_test

import (
	"strings"
	"testing"

	"github.com/jroedel/dmarc-monitor/business/types/email"
)

// A generated id borrows the sender's domain, so that a receiving server and
// the domain's own DMARC reporting agree about where the mail came from.
func TestGenerateBorrowsTheSenderDomain(t *testing.T) {
	id, err := email.GenerateMessageID(email.MustParse("dmarc@example.com"))
	if err != nil {
		t.Fatalf("GenerateMessageID: %v", err)
	}

	got := id.String()

	switch {
	case !strings.HasPrefix(got, "<"), !strings.HasSuffix(got, ">"):
		t.Errorf("id = %q, want it enclosed in angle brackets", got)
	case !strings.HasSuffix(got, "@example.com>"):
		t.Errorf("id = %q, want it to end in the sender's domain", got)
	}
}

// A zero Email has no domain to borrow. Falling back to a .invalid name is the
// honest answer: the id stays unique and well-formed, and it cannot be mistaken
// for one issued by a host that exists.
func TestGenerateFallsBackForAZeroSender(t *testing.T) {
	id, err := email.GenerateMessageID(email.Email{})
	if err != nil {
		t.Fatalf("GenerateMessageID: %v", err)
	}

	if !strings.HasSuffix(id.String(), "@dmarc-monitor.invalid>") {
		t.Errorf("id = %q, want the .invalid fallback domain", id)
	}
}

// Two messages must never share an id; a receiver is entitled to treat the
// second as a duplicate and drop it.
func TestGeneratedIDsAreUnique(t *testing.T) {
	from := email.MustParse("dmarc@example.com")
	seen := make(map[string]bool)

	for range 1000 {
		id, err := email.GenerateMessageID(from)
		if err != nil {
			t.Fatalf("GenerateMessageID: %v", err)
		}

		if seen[id.String()] {
			t.Fatalf("id %s was generated twice", id)
		}

		seen[id.String()] = true
	}
}

func TestParseMessageIDRoundTrips(t *testing.T) {
	const want = "<abc123.1700000000@example.com>"

	id, err := email.ParseMessageID("  " + want + "  ")
	if err != nil {
		t.Fatalf("ParseMessageID: %v", err)
	}

	if id.String() != want {
		t.Errorf("id = %q, want %q", id, want)
	}
}

func TestParseMessageIDRejects(t *testing.T) {
	tests := map[string]string{
		"empty":            "",
		"no brackets":      "abc@example.com",
		"no closing":       "<abc@example.com",
		"no opening":       "abc@example.com>",
		"no at":            "<abc.example.com>",
		"nothing before @": "<@example.com>",
		"nothing after @":  "<abc@>",

		// The one that is a security problem rather than a tidiness problem: a
		// bare CR or LF would end the header and let the remainder become
		// headers of its own.
		"line break": "<abc@example.com>\r\nBcc: attacker@evil.example",
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := email.ParseMessageID(input); err == nil {
				t.Errorf("ParseMessageID(%q) was accepted", input)
			}
		})
	}
}

func TestMessageIDZeroValue(t *testing.T) {
	var id email.MessageID

	switch {
	case !id.IsZero():
		t.Error("the zero value does not report itself as zero")
	case id.String() != "":
		t.Errorf("the zero value stringifies to %q, want empty", id)
	}
}
