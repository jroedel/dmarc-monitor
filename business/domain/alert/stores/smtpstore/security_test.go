package smtpstore

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// isLoopback decides whether a password may cross an unencrypted connection, so
// its edges matter more than its middle.
func TestIsLoopback(t *testing.T) {
	tests := map[string]bool{
		"localhost":             true,
		"LOCALHOST":             true,
		"  localhost  ":         true,
		"localhost.localdomain": true,
		"ip6-localhost":         true,
		"127.0.0.1":             true,
		"127.1.2.3":             true,
		"::1":                   true,

		"mail.your-server.de": false,
		"example.com":         false,
		"78.46.5.205":         false,
		"10.0.0.1":            false,
		"":                    false,

		// The shape of a name chosen to be mistaken for the real one.
		"localhost.evil.example": false,
		"notlocalhost":           false,
		"localhost.":             false,
	}

	for host, want := range tests {
		if got := isLoopback(host); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", host, got, want)
		}
	}
}

// The store repeats the config layer's refusal rather than trusting it. This is
// the last point before bytes leave the machine.
func TestPlaintextToARemoteHostIsRefused(t *testing.T) {
	store := NewStore(slog.New(slog.NewTextHandler(io.Discard, nil)), Config{
		Host:     "mail.your-server.de",
		Port:     25,
		Security: securityNone,
	})

	_, err := store.connect(context.Background())
	if err == nil {
		t.Fatal("connected in plaintext to a remote host")
	}

	if !strings.Contains(err.Error(), "plaintext") {
		t.Errorf("error does not explain the refusal: %v", err)
	}

	// It must refuse before dialling, not after — a refusal that depends on the
	// host being unreachable is not a refusal.
	if strings.Contains(err.Error(), "dialling") {
		t.Errorf("the host was contacted before being refused: %v", err)
	}
}
