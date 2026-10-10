// Package checkpoint remembers what the program has already seen between runs.
//
// It answers two questions, both of which are about not being annoying. Which
// reports have already been processed, so an overlapping or redelivered report
// does not produce a second alert; and which sending IPs are already known for
// a domain, so "a new source appeared" means something the first time and
// nothing the second.
//
// A JSON file under ~/.local/state is the right size of tool here. The data is
// small, it is written once per poll, it is read by one process, and an
// operator debugging a spurious alert can open it and see exactly what the
// program believed. A database would add a dependency and take that away.
package checkpoint

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/jroedel/dmarc-monitor/foundation/apppath"
)

// State is what carries over between runs. Its JSON is the file format, so the
// field tags are load-bearing: renaming one silently resets that memory and
// re-alerts on everything it used to know.
type State struct {
	Version         int                  `json:"version"`
	LastRun         time.Time            `json:"last_run,omitzero"`
	SeenReports     map[string]time.Time `json:"seen_reports,omitempty"`
	KnownSources    map[string][]string  `json:"known_sources,omitempty"`
	AlertedFindings map[string]time.Time `json:"alerted_findings,omitempty"`

	// RunningVersion is the build that last ran a scheduled cycle here. A
	// deploy replaces the binary from outside, so the first run of a new build
	// is the only moment anything on the server can notice that one landed.
	RunningVersion string `json:"running_version,omitempty"`
}

// Store is the state file.
type Store struct {
	path  string
	state State
}

// currentVersion is bumped when the file's meaning changes incompatibly. Open
// discards a file it does not understand rather than misreading it: losing the
// memory costs one noisy run, misreading it could cost a missed alert.
const currentVersion = 1

// retention is how long a processed report id or a sent finding is remembered.
// Long enough that no reporter's redelivery window reaches back past it, short
// enough that the file does not grow without bound.
const retention = 90 * 24 * time.Hour

// Name is the state file's filename, wherever it sits.
const Name = "state.json"

// DefaultPath returns where the state file lives: beside the binary, with the
// rest of the installation. A file left at the old ~/.local/state location is
// still used if it is there — losing the state costs one noisy run, but there
// is no reason to inflict even that.
func DefaultPath() (string, error) {
	beside, err := apppath.Beside(Name)
	if err != nil {
		return "", err
	}

	return apppath.Resolve(beside, legacyPath()), nil
}

// legacyPath is where the state lived before it moved beside the binary.
func legacyPath() string {
	return apppath.XDG("XDG_STATE_HOME", "dmarc-monitor", Name, ".local", "state")
}

// Open loads the state file, returning an empty store if it does not exist yet
// or was written by an incompatible version.
func Open(path string) (*Store, error) {
	s := Store{
		path: path,
		state: State{
			Version:         currentVersion,
			SeenReports:     make(map[string]time.Time),
			KnownSources:    make(map[string][]string),
			AlertedFindings: make(map[string]time.Time),
		},
	}

	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return &s, nil
	case err != nil:
		return nil, fmt.Errorf("checkpoint: reading %s: %w", path, err)
	}

	var loaded State
	if err := json.Unmarshal(data, &loaded); err != nil {
		return nil, fmt.Errorf("checkpoint: parsing %s: %w", path, err)
	}

	if loaded.Version != currentVersion {
		return &s, nil
	}

	if loaded.SeenReports != nil {
		s.state.SeenReports = loaded.SeenReports
	}
	if loaded.KnownSources != nil {
		s.state.KnownSources = loaded.KnownSources
	}
	if loaded.AlertedFindings != nil {
		s.state.AlertedFindings = loaded.AlertedFindings
	}
	s.state.LastRun = loaded.LastRun
	s.state.RunningVersion = loaded.RunningVersion

	return &s, nil
}

// Seen reports whether a report id has already been processed.
func (s *Store) Seen(reportID string) bool {
	_, ok := s.state.SeenReports[reportID]

	return ok
}

// MarkSeen records that a report id has been processed at t.
func (s *Store) MarkSeen(reportID string, t time.Time) {
	s.state.SeenReports[reportID] = t
}

// KnownSource reports whether an IP has been seen sending for a domain before.
func (s *Store) KnownSource(domain, ip string) bool {
	return slices.Contains(s.state.KnownSources[domain], ip)
}

// LearnSource records an IP as a known source for a domain. Learning happens
// after triage, not before, so that the run which first sees an IP is the run
// that can call it new.
func (s *Store) LearnSource(domain, ip string) {
	if s.KnownSource(domain, ip) {
		return
	}

	s.state.KnownSources[domain] = append(s.state.KnownSources[domain], ip)
}

// KnownSourceCount returns how many sources are remembered for a domain. Zero
// means the domain has never been seen, which is why the first run of the
// program does not report every source as new.
func (s *Store) KnownSourceCount(domain string) int {
	return len(s.state.KnownSources[domain])
}

// Alerted reports whether a finding fingerprint was sent within cooldown of t.
func (s *Store) Alerted(fingerprint string, t time.Time, cooldown time.Duration) bool {
	sent, ok := s.state.AlertedFindings[fingerprint]
	if !ok {
		return false
	}

	return t.Sub(sent) < cooldown
}

// MarkAlerted records that a finding fingerprint went out at t.
func (s *Store) MarkAlerted(fingerprint string, t time.Time) {
	s.state.AlertedFindings[fingerprint] = t
}

// LastRun returns when the last successful cycle finished; the zero time if
// this is the first ever run.
func (s *Store) LastRun() time.Time { return s.state.LastRun }

// RunningVersion returns the build that last ran a scheduled cycle here; empty
// if none was ever recorded, which is every installation that predates it.
func (s *Store) RunningVersion() string { return s.state.RunningVersion }

// RecordVersion notes that version is the build running now and writes the
// file at once.
//
// It writes immediately rather than waiting for Save, because Save happens only
// after a cycle succeeds. A deploy whose first cycle then failed to reach the
// mailbox would otherwise announce itself again on every run until one did.
// LastRun is left alone: recording a version is not a successful cycle.
func (s *Store) RecordVersion(version string) error {
	if s.state.RunningVersion == version {
		return nil
	}

	s.state.RunningVersion = version

	return s.write()
}

// Save prunes expired entries and writes the file.
func (s *Store) Save(now time.Time) error {
	s.state.LastRun = now
	s.prune(now)

	return s.write()
}

// write writes the file atomically: a temporary file in the same directory,
// then a rename. A half-written state file that lost the seen-report list would
// re-alert on everything in it.
func (s *Store) write() error {
	s.state.Version = currentVersion

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("checkpoint: creating %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("checkpoint: encoding state: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "state-*.json")
	if err != nil {
		return fmt.Errorf("checkpoint: creating temporary file in %s: %w", dir, err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()

		return fmt.Errorf("checkpoint: writing temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("checkpoint: closing temporary file: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("checkpoint: securing temporary file: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("checkpoint: replacing %s: %w", s.path, err)
	}

	return nil
}

// prune drops entries older than retention. Known sources are never pruned:
// forgetting an IP would make it new again and produce exactly the false alarm
// the map exists to prevent.
func (s *Store) prune(now time.Time) {
	cutoff := now.Add(-retention)

	maps.DeleteFunc(s.state.SeenReports, func(_ string, t time.Time) bool {
		return t.Before(cutoff)
	})
	maps.DeleteFunc(s.state.AlertedFindings, func(_ string, t time.Time) bool {
		return t.Before(cutoff)
	})
}
