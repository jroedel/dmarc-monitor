package main

import (
	"os"
	"strings"
	"testing"
)

// The update notice is the one mail nobody is waiting for, so it has to justify
// itself in the subject line and the first two lines of the body: which machine,
// and which version. Anyone who wants more has the release link.
func TestUpdateNotice(t *testing.T) {
	update := installed{
		from: "v0.1.0",
		to:   "v0.2.0",
		url:  "https://github.com/jroedel/dmarc-monitor/releases/tag/v0.2.0",
	}

	notice := updateNotice(update, "/home/webmaster/.local/bin/dmarc-monitor")

	host, err := os.Hostname()
	if err != nil {
		t.Fatalf("Hostname: %v", err)
	}

	switch {
	case !strings.Contains(notice.Subject, "v0.2.0"):
		t.Errorf("subject does not name the new version: %q", notice.Subject)
	case !strings.Contains(notice.Subject, host):
		t.Errorf("subject does not name the machine: %q", notice.Subject)
	case strings.ContainsAny(notice.Subject, "\r\n"):
		t.Errorf("subject spans lines: %q", notice.Subject)
	}

	for _, want := range []string{
		"v0.1.0",
		"v0.2.0",
		"/home/webmaster/.local/bin/dmarc-monitor",
		update.url,
		"takes effect at the next scheduled run",
		"ALERT_ON_UPDATE=false",
	} {
		if !strings.Contains(notice.Body, want) {
			t.Errorf("body is missing %q", want)
		}
	}

	t.Logf("Subject: %s\n\n%s", notice.Subject, notice.Body)
}

// A build that was never stamped reports "dev". The notice must still read
// sensibly rather than showing an empty field where a version belongs.
func TestUpdateNoticeFromDevBuild(t *testing.T) {
	notice := updateNotice(installed{from: "dev", to: "v0.1.0"}, "/usr/local/bin/dmarc-monitor")

	if !strings.Contains(notice.Body, "dev") {
		t.Errorf("body does not say what it upgraded from: %q", notice.Body)
	}
}
