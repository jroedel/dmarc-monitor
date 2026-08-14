// Package lockfile stops two copies of the program running at once.
//
// It exists because of how this is deployed: a crontab entry that fires every
// minute. A cycle that takes longer than a minute — a slow mail server, a
// mailbox with a backlog, a local model thinking — would otherwise be joined by
// a second copy, then a third, each logging in to the same mailbox, racing to
// flag the same messages and to write the same state file. Nothing about that
// fails loudly; it just quietly duplicates alerts and corrupts memory.
//
// The lock is advisory and held by the open file descriptor, so it is released
// when the process exits by any means, including a kill or a crash. There is no
// stale lock to clean up and no PID file to go wrong.
package lockfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrHeld is returned by Acquire when another process holds the lock. It is not
// a failure: under a once-a-minute cron the normal response is to exit quietly
// and let the running copy finish.
var ErrHeld = errors.New("lockfile: held by another process")

// Lock is a held file lock.
type Lock struct {
	file *os.File
}

// Acquire takes the lock at path without blocking, creating the file and its
// directory if needed.
func Acquire(path string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("lockfile: creating %s: %w", filepath.Dir(path), err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lockfile: opening %s: %w", path, err)
	}

	if err := flock(f); err != nil {
		f.Close()

		if errors.Is(err, ErrHeld) {
			return nil, ErrHeld
		}

		return nil, fmt.Errorf("lockfile: locking %s: %w", path, err)
	}

	return &Lock{file: f}, nil
}

// Release drops the lock. Safe to call on a nil Lock, so callers can defer it
// without first checking whether they got one.
func (l *Lock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}

	err := l.file.Close()
	l.file = nil

	return err
}
