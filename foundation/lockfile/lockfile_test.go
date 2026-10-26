package lockfile_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jroedel/dmarc-monitor/foundation/lockfile"
)

// helperEnv turns this test binary into a one-shot contender for a lock, so the
// contention test can use a genuinely separate process. flock is held by the
// file description rather than the process, so a second Acquire inside this
// process would not be refused — and it is the cron case, two processes, that
// actually needs proving.
const helperEnv = "DMARC_LOCKFILE_HELPER_PATH"

// helperWaitEnv, when set to a duration, makes the contender use AcquireWait
// for that long instead of trying once.
const helperWaitEnv = "DMARC_LOCKFILE_HELPER_WAIT"

const (
	exitHeld     = 3
	exitAcquired = 4
)

func TestMain(m *testing.M) {
	if path := os.Getenv(helperEnv); path != "" {
		acquire := lockfile.Acquire
		if wait, err := time.ParseDuration(os.Getenv(helperWaitEnv)); err == nil {
			acquire = func(path string) (*lockfile.Lock, error) {
				return lockfile.AcquireWait(context.Background(), path, wait)
			}
		}

		_, err := acquire(path)
		switch {
		case errors.Is(err, lockfile.ErrHeld):
			os.Exit(exitHeld)
		case err != nil:
			os.Exit(1)
		default:
			os.Exit(exitAcquired)
		}
	}

	os.Exit(m.Run())
}

func TestAcquireAndRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "run.lock")

	lock, err := lockfile.Acquire(path)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	if err := lock.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// Releasing twice must be harmless; callers defer it unconditionally.
	if err := lock.Release(); err != nil {
		t.Errorf("second Release: %v", err)
	}

	again, err := lockfile.Acquire(path)
	if err != nil {
		t.Fatalf("re-Acquire after release: %v", err)
	}
	again.Release()
}

// The case that matters: a second copy must be told the lock is held rather
// than joining in and duplicating the work.
func TestSecondProcessIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.lock")

	lock, err := lockfile.Acquire(path)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer lock.Release()

	if got := contend(t, path); got != exitHeld {
		t.Errorf("contender exited %d, want %d (ErrHeld)", got, exitHeld)
	}
}

// And once the first copy is done, the next run must get straight in.
func TestLockIsFreedForTheNextRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.lock")

	lock, err := lockfile.Acquire(path)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	if got := contend(t, path); got != exitAcquired {
		t.Errorf("contender exited %d, want %d (acquired)", got, exitAcquired)
	}
}

// A cycle that meets a deploy's lock waits it out rather than skipping: it gets
// the lock once the holder lets go.
func TestWaitTakesTheLockOnceFreed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.lock")

	lock, err := lockfile.Acquire(path)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	cmd := contender(path, "10s")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the contender: %v", err)
	}

	time.Sleep(500 * time.Millisecond)
	if err := lock.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	if got := exitCode(t, cmd.Wait()); got != exitAcquired {
		t.Errorf("contender exited %d, want %d (acquired after waiting)", got, exitAcquired)
	}
}

// And a lock that is never let go is reported as held once the wait is over,
// not waited on for ever.
func TestWaitGivesUpOnAStuckLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.lock")

	lock, err := lockfile.Acquire(path)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer lock.Release()

	start := time.Now()
	got := exitCode(t, contender(path, "300ms").Run())

	if got != exitHeld {
		t.Errorf("contender exited %d, want %d (ErrHeld)", got, exitHeld)
	}
	if elapsed := time.Since(start); elapsed < 300*time.Millisecond {
		t.Errorf("contender gave up after %s, before its 300ms wait was over", elapsed)
	}
}

func TestReleaseOnNilIsSafe(t *testing.T) {
	var lock *lockfile.Lock

	if err := lock.Release(); err != nil {
		t.Errorf("Release on a nil lock: %v", err)
	}
}

// contend runs this test binary as a separate process that tries the lock once,
// and returns its exit code.
func contend(t *testing.T, path string) int {
	t.Helper()

	return exitCode(t, contender(path, "").Run())
}

// contender is this test binary set up to contend for the lock at path, with
// AcquireWait for wait if it is not empty and a single Acquire if it is.
func contender(path, wait string) *exec.Cmd {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), helperEnv+"="+path, helperWaitEnv+"="+wait)

	return cmd
}

// exitCode is the exit code a contender's Run or Wait error stands for.
func exitCode(t *testing.T, err error) int {
	t.Helper()

	if err == nil {
		return 0
	}

	exitErr, ok := errors.AsType[*exec.ExitError](err)
	if !ok {
		t.Fatalf("running the contender: %v", err)
	}

	return exitErr.ExitCode()
}
