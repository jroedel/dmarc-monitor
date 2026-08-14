package smtpstore

import (
	"net"
	"strings"
)

// The connection modes this store understands. They arrive as strings because
// the config layer owns their vocabulary and has already validated them; these
// constants exist so the switches in connect read as decisions rather than as
// string literals.
const (
	securityTLS      = "tls"
	securitySTARTTLS = "starttls"
	securityNone     = "none"
)

// isLoopback reports whether host names the machine this is running on.
//
// A string test, not a DNS lookup. This is what decides whether plaintext is
// permitted, and a decision of that kind must not be able to change because a
// resolver was poisoned or a hosts file was edited: "localhost" resolving
// somewhere unexpected should cost a failed connection, never a password sent
// in the clear to a stranger.
func isLoopback(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost", "localhost.localdomain", "ip6-localhost":
		return true
	}

	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}

	return false
}
