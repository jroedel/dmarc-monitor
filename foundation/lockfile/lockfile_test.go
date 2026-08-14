package lockfile_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jroedel/dmarc-monitor/foundation/lockfile"
)

// helperEnv turns this test binary into a one-shot contender for a lock, so the
// contention test can use a genuinely separate process. flock is held by the
// file description rather than the process, so a second Acquire inside this
// process would not be refused — and it is the cron case, two processes, that
// actually needs proving.
const helperEnv = "DMARC_LOCKFILE_HELPER_PATH"

const (
	exitHeld     = 3
	exitAcquired = 4
)

func TestMain(m *testing.M) {
	if path := os.Getenv(helperEnv); path != "" {
		_, err := lockfile.Acquire(path)
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

// The case that matters under a once-a-minute cron: a second copy must be told
// the lock is held rather than joining in and duplicating the work.
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

// And once the first copy is done, the next minute's run must get straight in.
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

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), helperEnv+"="+path)

	err := cmd.Run()
	if err == nil {
		return 0
	}

	exitErr, ok := errors.AsType[*exec.ExitError](err)
	if !ok {
		t.Fatalf("running the contender: %v", err)
	}

	return exitErr.ExitCode()
}
