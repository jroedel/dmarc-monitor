package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests are about not installing the wrong thing. A bad update here runs
// as the user that holds the mailbox password, so every refusal below matters
// more than the update it declines.

const assetName = "dmarc-monitor-linux-amd64"

// fakeGitHub serves a release, its asset and a checksums file.
type fakeGitHub struct {
	server     *httptest.Server
	tag        string
	binary     []byte
	checksums  string
	prerelease bool
	draft      bool
	omitAsset  bool
	omitSums   bool
	status     int
}

func newFakeGitHub(t *testing.T, f *fakeGitHub) *fakeGitHub {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/repos/owner/repo/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		if f.status != 0 && f.status != http.StatusOK {
			w.WriteHeader(f.status)

			return
		}

		var assets []string
		if !f.omitAsset {
			assets = append(assets, fmt.Sprintf(`{"name":%q,"browser_download_url":"%s/asset"}`, assetName, f.server.URL))
		}
		if !f.omitSums {
			assets = append(assets, fmt.Sprintf(`{"name":"checksums.txt","browser_download_url":"%s/checksums"}`, f.server.URL))
		}

		fmt.Fprintf(w, `{"tag_name":%q,"draft":%t,"prerelease":%t,"html_url":"https://example.invalid/r","assets":[%s]}`,
			f.tag, f.draft, f.prerelease, strings.Join(assets, ","))
	})

	mux.HandleFunc("/asset", func(w http.ResponseWriter, _ *http.Request) {
		w.Write(f.binary)
	})

	mux.HandleFunc("/checksums", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, f.checksums)
	})

	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)

	// The handlers close over server.URL, which only exists once started.
	return f
}

func sum(b []byte) string {
	h := sha256.Sum256(b)

	return hex.EncodeToString(h[:])
}

func newUpdater(t *testing.T, gh *fakeGitHub, current, target string) *Updater {
	t.Helper()

	u := New(Config{
		Repo:           "owner/repo",
		CurrentVersion: current,
		AssetName:      assetName,
		ExecutablePath: target,
	})
	u.apiURL = gh.server.URL

	return u
}

func installedBinary(t *testing.T) (path string, original []byte) {
	t.Helper()

	original = []byte("#!/bin/sh\necho old\n")
	path = filepath.Join(t.TempDir(), "dmarc-monitor")

	if err := os.WriteFile(path, original, 0o755); err != nil {
		t.Fatalf("writing the installed binary: %v", err)
	}

	return path, original
}

func TestUpdatesToANewerRelease(t *testing.T) {
	newBinary := []byte("#!/bin/sh\necho new\n")
	gh := newFakeGitHub(t, &fakeGitHub{tag: "v1.2.0", binary: newBinary})
	gh.checksums = fmt.Sprintf("%s  %s\n", sum(newBinary), assetName)

	target, _ := installedBinary(t)
	u := newUpdater(t, gh, "v1.1.0", target)

	release, available, err := u.Latest(t.Context())
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if !available {
		t.Fatal("a newer release was not offered")
	}
	if release.Version != "v1.2.0" {
		t.Errorf("version = %q, want v1.2.0", release.Version)
	}

	if err := u.Apply(t.Context(), release); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	installed, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("reading the installed binary: %v", err)
	}
	if string(installed) != string(newBinary) {
		t.Error("the binary was not replaced")
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("installed binary is not executable: mode %#o", info.Mode().Perm())
	}
}

// The single most important test here: a tampered or truncated download must
// leave the working binary exactly where it was.
func TestRefusesAChecksumMismatch(t *testing.T) {
	gh := newFakeGitHub(t, &fakeGitHub{tag: "v1.2.0", binary: []byte("malicious")})
	gh.checksums = fmt.Sprintf("%s  %s\n", sum([]byte("what was published")), assetName)

	target, original := installedBinary(t)
	u := newUpdater(t, gh, "v1.1.0", target)

	release, available, err := u.Latest(t.Context())
	if err != nil || !available {
		t.Fatalf("Latest: %v (available=%v)", err, available)
	}

	err = u.Apply(t.Context(), release)
	if err == nil {
		t.Fatal("installed a binary that did not match its checksum")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("error does not explain itself: %v", err)
	}

	installed, _ := os.ReadFile(target)
	if string(installed) != string(original) {
		t.Fatal("the working binary was replaced despite the mismatch")
	}

	// And nothing may be left lying around next to it.
	entries, _ := os.ReadDir(filepath.Dir(target))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".dmarc-monitor-update-") {
			t.Errorf("a failed update left %s behind", e.Name())
		}
	}
}

// A release with no checksums.txt cannot be verified, so it is not installed.
func TestRefusesAReleaseWithoutChecksums(t *testing.T) {
	binary := []byte("new")
	gh := newFakeGitHub(t, &fakeGitHub{tag: "v1.2.0", binary: binary, omitSums: true})

	target, original := installedBinary(t)
	u := newUpdater(t, gh, "v1.1.0", target)

	release, _, err := u.Latest(t.Context())
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}

	if err := u.Apply(t.Context(), release); err == nil {
		t.Fatal("installed an unverifiable release")
	}

	installed, _ := os.ReadFile(target)
	if string(installed) != string(original) {
		t.Error("the working binary was replaced")
	}
}

// Prereleases and drafts are somebody testing something. They must never reach
// a server that is quietly updating itself twice a day.
func TestIgnoresPrereleasesAndDrafts(t *testing.T) {
	for name, gh := range map[string]*fakeGitHub{
		"prerelease": {tag: "v2.0.0", binary: []byte("x"), prerelease: true},
		"draft":      {tag: "v2.0.0", binary: []byte("x"), draft: true},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeGitHub(t, gh)
			u := newUpdater(t, fake, "v1.0.0", filepath.Join(t.TempDir(), "bin"))

			_, available, err := u.Latest(t.Context())
			if err != nil {
				t.Fatalf("Latest: %v", err)
			}
			if available {
				t.Errorf("a %s was offered as an update", name)
			}
		})
	}
}

// A repository with no releases yet is an ordinary state, not a failure — the
// program must run normally and simply not update.
func TestNoReleasesIsNotAnError(t *testing.T) {
	gh := newFakeGitHub(t, &fakeGitHub{status: http.StatusNotFound})
	u := newUpdater(t, gh, "v1.0.0", filepath.Join(t.TempDir(), "bin"))

	_, available, err := u.Latest(t.Context())
	if err != nil {
		t.Fatalf("Latest on a repo with no releases: %v", err)
	}
	if available {
		t.Error("an update was offered by a repo with no releases")
	}
}

func TestSameVersionIsNotOffered(t *testing.T) {
	gh := newFakeGitHub(t, &fakeGitHub{tag: "v1.2.0", binary: []byte("x")})
	u := newUpdater(t, gh, "v1.2.0", filepath.Join(t.TempDir(), "bin"))

	_, available, err := u.Latest(t.Context())
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if available {
		t.Error("the running version was offered to itself")
	}
}

// A release built for another platform, or one whose upload failed, must be
// reported rather than silently skipped — it means the pipeline is broken.
func TestMissingAssetIsReported(t *testing.T) {
	gh := newFakeGitHub(t, &fakeGitHub{tag: "v1.2.0", omitAsset: true})
	u := newUpdater(t, gh, "v1.1.0", filepath.Join(t.TempDir(), "bin"))

	_, available, err := u.Latest(t.Context())
	switch {
	case err == nil:
		t.Fatal("a release with no matching asset was accepted")
	case available:
		t.Error("an unusable release was offered")
	case !strings.Contains(err.Error(), assetName):
		t.Errorf("error does not name the missing asset: %v", err)
	}
}

func TestApplyIsCancellable(t *testing.T) {
	binary := []byte("new")
	gh := newFakeGitHub(t, &fakeGitHub{tag: "v1.2.0", binary: binary})
	gh.checksums = fmt.Sprintf("%s  %s\n", sum(binary), assetName)

	target, original := installedBinary(t)
	u := newUpdater(t, gh, "v1.1.0", target)

	release, _, err := u.Latest(t.Context())
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := u.Apply(ctx, release); err == nil {
		t.Error("a cancelled update reported success")
	}

	installed, _ := os.ReadFile(target)
	if string(installed) != string(original) {
		t.Error("a cancelled update replaced the binary")
	}
}
