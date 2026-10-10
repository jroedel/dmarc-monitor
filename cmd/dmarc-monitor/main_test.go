package main

import (
	"os"
	"strings"
	"testing"
)

// The deploy notice is the one mail nobody is waiting for, so it has to justify
// itself in the subject line and the first lines of the body: which machine,
// and which build. Anyone who wants more has the commit link.
func TestDeployNotice(t *testing.T) {
	d := deployed{
		from:   "v0.1.5",
		to:     "v0.1.5-3-gabc1234",
		commit: "abc1234def5678",
	}

	notice := deployNotice(d, "/home/webmaster/dmarc-monitor/dmarc-monitor")

	host, err := os.Hostname()
	if err != nil {
		t.Fatalf("Hostname: %v", err)
	}

	switch {
	case !strings.Contains(notice.Subject, d.to):
		t.Errorf("subject does not name the new build: %q", notice.Subject)
	case !strings.Contains(notice.Subject, host):
		t.Errorf("subject does not name the machine: %q", notice.Subject)
	case strings.ContainsAny(notice.Subject, "\r\n"):
		t.Errorf("subject spans lines: %q", notice.Subject)
	}

	for _, want := range []string{
		"v0.1.5",
		"v0.1.5-3-gabc1234",
		"/home/webmaster/dmarc-monitor/dmarc-monitor",
		sourceRepo + "/commit/abc1234def5678",
		"ALERT_ON_UPDATE=false",
	} {
		if !strings.Contains(notice.Body, want) {
			t.Errorf("body is missing %q", want)
		}
	}

	t.Logf("Subject: %s\n\n%s", notice.Subject, notice.Body)
}

// The first deploy after the switch to ssh finds no version recorded, and a
// hand-built binary has no commit. Neither may leave an empty field or a link
// to nothing.
func TestDeployNoticeWithNothingRecorded(t *testing.T) {
	notice := deployNotice(deployed{to: "dev"}, "/usr/local/bin/dmarc-monitor")

	if !strings.Contains(notice.Body, "(not recorded)") {
		t.Errorf("body does not say the previous build is unknown: %q", notice.Body)
	}

	if strings.Contains(notice.Body, "/commit/") {
		t.Errorf("body links a commit it does not have: %q", notice.Body)
	}
}
