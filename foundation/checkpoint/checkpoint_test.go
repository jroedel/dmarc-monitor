package checkpoint

import (
	"path/filepath"
	"testing"
	"time"
)

// RecordVersion is what the deploy notice hangs on, so the three moments that
// matter are pinned: an installation that never recorded a version, the first
// run of a new build, and every run after it.
func TestRecordVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), Name)

	steps := []struct {
		version string
		want    string
	}{
		{"v0.1.5", ""},
		{"v0.1.5", "v0.1.5"},
		{"v0.1.5-3-gabc1234", "v0.1.5"},
	}

	for _, step := range steps {
		// Reopened each time, because the point is that the version survives
		// between runs without a cycle having called Save.
		s, err := Open(path)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}

		if got := s.RunningVersion(); got != step.want {
			t.Errorf("before recording %q: RunningVersion = %q, want %q", step.version, got, step.want)
		}

		if err := s.RecordVersion(step.version); err != nil {
			t.Fatalf("RecordVersion(%q): %v", step.version, err)
		}
	}
}

// Recording a version is not a successful cycle. If it moved LastRun, a deploy
// whose first cycle failed would look, from the state file, like one that ran.
func TestRecordVersionLeavesLastRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), Name)

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ran := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	if err := s.Save(ran); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := s.RecordVersion("v0.2.0"); err != nil {
		t.Fatalf("RecordVersion: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if !reopened.LastRun().Equal(ran) {
		t.Errorf("LastRun = %v, want %v", reopened.LastRun(), ran)
	}
}

// An outage, run by run, as the twice-daily schedule produces it: mailed at
// the first failure, quiet at the next, mailed again a day on -- including
// when the run a day on starts a moment earlier than the one that mailed --
// and closed by the first success. Every step reopens the file, because a
// failed cycle never calls Save and the outage must survive on its own.
func TestOutage(t *testing.T) {
	path := filepath.Join(t.TempDir(), Name)
	start := time.Date(2026, 10, 10, 13, 0, 1, 0, time.UTC)

	open := func() *Store {
		t.Helper()

		s, err := Open(path)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}

		return s
	}

	fail := func(at time.Time, wantDue bool) {
		t.Helper()

		s := open()
		if err := s.RecordFailure(at); err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}

		if got := s.FailureMailDue(at); got != wantDue {
			t.Fatalf("at %v: FailureMailDue = %v, want %v", at, got, wantDue)
		}

		if wantDue {
			if err := s.MarkFailureMailed(at); err != nil {
				t.Fatalf("MarkFailureMailed: %v", err)
			}
		}
	}

	fail(start, true)
	fail(start.Add(12*time.Hour), false)
	fail(start.Add(24*time.Hour-time.Second), true)
	fail(start.Add(36*time.Hour), false)

	if o, failing := open().Failing(); !failing || !o.Since.Equal(start) {
		t.Fatalf("Failing = %v, %v; want an outage since %v", o, failing, start)
	}

	o, ended, err := open().RecordRecovery()
	switch {
	case err != nil:
		t.Fatalf("RecordRecovery: %v", err)
	case !ended:
		t.Fatal("RecordRecovery found no outage")
	case !o.Since.Equal(start), o.Mailed.IsZero():
		t.Fatalf("outage = %+v; want since %v, mailed", o, start)
	}

	if _, failing := open().Failing(); failing {
		t.Fatal("still failing after recovery")
	}

	if _, ended, _ := open().RecordRecovery(); ended {
		t.Fatal("a second recovery reported an outage")
	}
}

// A failure whose mail could not be sent -- the relay is down too -- must be
// retried at the next failed run, not a day later.
func TestUnmailedFailureStaysDue(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), Name))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	start := time.Date(2026, 10, 10, 13, 0, 0, 0, time.UTC)
	if err := s.RecordFailure(start); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}

	if !s.FailureMailDue(start.Add(12 * time.Hour)) {
		t.Error("an outage nobody was told about is not due at the next run")
	}
}
