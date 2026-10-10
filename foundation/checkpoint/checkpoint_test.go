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
