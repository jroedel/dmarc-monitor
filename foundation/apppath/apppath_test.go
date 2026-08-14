package apppath_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jroedel/dmarc-monitor/foundation/apppath"
)

func touch(t *testing.T, path string) string {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	return path
}

// The rule that keeps an existing installation working: a file that is already
// somewhere is found there, and only a file that does not exist yet goes to the
// preferred place.
func TestResolve(t *testing.T) {
	dir := t.TempDir()
	preferred := filepath.Join(dir, "beside", "credentials.env")
	legacy := filepath.Join(dir, "legacy", "credentials.env")

	t.Run("neither exists: the preferred path", func(t *testing.T) {
		if got := apppath.Resolve(preferred, legacy); got != preferred {
			t.Errorf("Resolve = %q, want %q", got, preferred)
		}
	})

	t.Run("only the legacy exists: the legacy path", func(t *testing.T) {
		touch(t, legacy)
		defer os.Remove(legacy)

		if got := apppath.Resolve(preferred, legacy); got != legacy {
			t.Errorf("Resolve = %q, want the existing legacy file %q", got, legacy)
		}
	})

	t.Run("both exist: the preferred path wins", func(t *testing.T) {
		touch(t, legacy)
		touch(t, preferred)
		defer os.Remove(legacy)
		defer os.Remove(preferred)

		if got := apppath.Resolve(preferred, legacy); got != preferred {
			t.Errorf("Resolve = %q, want %q", got, preferred)
		}
	})

	t.Run("empty candidates are skipped", func(t *testing.T) {
		if got := apppath.Resolve("", preferred, ""); got != preferred {
			t.Errorf("Resolve = %q, want %q", got, preferred)
		}
		if got := apppath.Resolve(); got != "" {
			t.Errorf("Resolve() = %q, want empty", got)
		}
	})
}

func TestXDG(t *testing.T) {
	t.Run("honours the environment variable", func(t *testing.T) {
		t.Setenv("XDG_DATA_HOME", "/somewhere/data")

		got := apppath.XDG("XDG_DATA_HOME", "dmarc-monitor", "credentials.env", ".local", "share")
		if want := "/somewhere/data/dmarc-monitor/credentials.env"; got != want {
			t.Errorf("XDG = %q, want %q", got, want)
		}
	})

	t.Run("falls back under the home directory", func(t *testing.T) {
		t.Setenv("XDG_DATA_HOME", "")
		t.Setenv("HOME", "/home/tester")

		got := apppath.XDG("XDG_DATA_HOME", "dmarc-monitor", "credentials.env", ".local", "share")
		if want := "/home/tester/.local/share/dmarc-monitor/credentials.env"; got != want {
			t.Errorf("XDG = %q, want %q", got, want)
		}
	})
}

func TestBesideTheBinary(t *testing.T) {
	dir, err := apppath.Dir()
	if err != nil {
		t.Fatalf("Dir: %v", err)
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("Dir returned a relative path: %q", dir)
	}

	beside, err := apppath.Beside("credentials.env")
	if err != nil {
		t.Fatalf("Beside: %v", err)
	}

	if got, want := filepath.Dir(beside), dir; got != want {
		t.Errorf("Beside is in %q, want %q", got, want)
	}
	if got, want := filepath.Base(beside), "credentials.env"; got != want {
		t.Errorf("Beside names %q, want %q", got, want)
	}
}
