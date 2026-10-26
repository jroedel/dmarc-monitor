// Package lockfile stops two copies of the program running at once.
//
// Two copies would each log in to the same mailbox, race to flag the same
// messages and to write the same state file. Nothing about that fails loudly;
// it just quietly duplicates alerts and corrupts memory.
//
// The deploy takes the same lock, with flock(1) on the server, while it backs
// up the state file and swaps the binary, so a cycle and a deploy never
// overlap either.
//
// The lock is advisory and held by the open file descriptor, so it is released
// when the process exits by any means, including a kill or a crash. There is no
// stale lock to clean up and no PID file to go wrong.
package lockfile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ErrHeld is returned by Acquire when another process holds the lock, and by
// AcquireWait when it still does once the wait is over.
var ErrHeld = errors.New("lockfile: held by another process")

// retryInterval is how often AcquireWait tries again. A cycle takes seconds and
// a deploy's hold less, so a second's delay is nothing next to either.
const retryInterval = time.Second

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

// AcquireWait takes the lock at path like Acquire, but while another process
// holds it, keeps trying until it is free or wait has passed. It returns
// ErrHeld if the lock is still held at the end, and the context's cause if ctx
// ends first.
func AcquireWait(ctx context.Context, path string, wait time.Duration) (*Lock, error) {
	deadline := time.Now().Add(wait)

	for {
		lock, err := Acquire(path)
		if !errors.Is(err, ErrHeld) {
			return lock, err
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, ErrHeld
		}

		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-time.After(min(retryInterval, remaining)):
		}
	}
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
