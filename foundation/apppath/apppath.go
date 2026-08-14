// Package apppath decides where the program's files live.
//
// Everything belonging to one installation sits in one directory, beside the
// binary: the credentials, the state, the lock. That is a deliberate choice
// against the XDG layout this used to follow, and it is about deployment rather
// than taste. A server install is now a directory you can list, copy, back up
// or delete in one go — `~/dmarc-monitor/` holds the whole thing — and setting
// it up is two steps: write the credentials there, add the crontab line.
//
// The XDG paths are still honoured when a file is actually sitting in one, so
// an installation made before this change keeps working without being touched.
// Nothing is migrated automatically; moving somebody's credentials file out
// from under them is not a thing a monitoring program should do.
package apppath

import (
	"fmt"
	"os"
	"path/filepath"
)

// Dir returns the directory holding the running binary, with symlinks resolved
// so that a symlinked binary keeps its files beside the real one rather than
// beside the link.
func Dir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("apppath: locating the running binary: %w", err)
	}

	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	return filepath.Dir(exe), nil
}

// Beside returns the path of name in the binary's directory.
func Beside(name string) (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, name), nil
}

// Resolve returns the first candidate that exists, or the first candidate if
// none do — so a file that is already somewhere is found there, and a file that
// does not exist yet is created in the preferred place.
//
// Empty candidates are skipped, which lets a caller pass a path it could not
// compute without branching around it.
func Resolve(candidates ...string) string {
	var first string

	for _, path := range candidates {
		if path == "" {
			continue
		}

		if first == "" {
			first = path
		}

		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return first
}

// XDG returns a path under an XDG base directory, honouring the environment
// variable and otherwise falling back to the conventional location under the
// home directory. It exists only to find files left by an older installation.
//
//	XDG("XDG_DATA_HOME", "dmarc-monitor", "credentials.env", ".local", "share")
//
// Returns "" when the home directory cannot be determined, which Resolve skips.
func XDG(envVar, sub, name string, fallback ...string) string {
	if dir := os.Getenv(envVar); dir != "" {
		return filepath.Join(dir, sub, name)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	parts := append([]string{home}, fallback...)
	parts = append(parts, sub, name)

	return filepath.Join(parts...)
}
