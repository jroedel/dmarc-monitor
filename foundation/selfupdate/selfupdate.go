// Package selfupdate replaces the running binary with the newest published
// GitHub release.
//
// It exists so that the whole deployment is one crontab entry: the line
// downloads the binary if it is missing and runs it, and the binary keeps
// itself current from then on. Nobody has to log in to the server to ship a
// fix.
//
// That convenience is also the risk, so the rules are narrow.
//
// Only *published releases* are considered — never a branch, never a commit on
// main. Cutting a release is a deliberate act, which keeps an ordinary push
// from reaching production unattended. Prereleases and drafts are ignored.
//
// Every download is verified against the checksums.txt published alongside it
// before anything is replaced, and a mismatch aborts without touching the
// installed binary. The program this updates holds a mailbox password and can
// send mail as the domain, so an unverified binary is not a lesser problem than
// no update at all.
//
// The replacement is a rename over the existing file, which on Unix leaves the
// running process on its old inode, untouched. The new binary takes effect at
// the next cron run rather than mid-cycle — there is no re-exec, no restart,
// and no window where a half-written file is what cron finds.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrNoAsset is returned when a release exists but carries nothing built for
// this platform — a release that failed halfway, usually.
var ErrNoAsset = errors.New("selfupdate: release has no asset for this platform")

// maxAsset caps a download. The binary is around 15 MB; 256 MB is far beyond
// any honest release and short of anything that would fill a small server's
// disk before the write failed.
const maxAsset = 256 << 20

// Config describes where updates come from and what is running now.
type Config struct {
	// Repo is "owner/name" on GitHub.
	Repo string

	// CurrentVersion is the running build's version, as stamped at link time.
	// The zero value and "dev" both mean an unversioned local build, which is
	// always considered older than a release.
	CurrentVersion string

	// AssetName is the release asset to install, e.g.
	// "dmarc-monitor-linux-amd64".
	AssetName string

	// ExecutablePath is the file to replace. Empty means the running binary.
	ExecutablePath string

	// Timeout bounds the whole check-and-download.
	Timeout time.Duration
}

// Updater checks for and applies updates.
type Updater struct {
	cfg    Config
	http   *http.Client
	apiURL string
}

// Release is a published release worth installing.
type Release struct {
	Version     string
	AssetURL    string
	ChecksumURL string
	PublishedAt time.Time
	URL         string
}

const defaultTimeout = 5 * time.Minute

// New constructs an updater.
func New(cfg Config) *Updater {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}

	return &Updater{
		cfg:    cfg,
		http:   &http.Client{Timeout: cfg.Timeout},
		apiURL: "https://api.github.com",
	}
}

// Latest returns the newest published release and whether it is newer than what
// is running.
func (u *Updater) Latest(ctx context.Context) (Release, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, u.cfg.Timeout)
	defer cancel()

	url := fmt.Sprintf("%s/repos/%s/releases/latest", u.apiURL, u.cfg.Repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Release{}, false, fmt.Errorf("selfupdate: building request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := u.http.Do(req)
	if err != nil {
		return Release{}, false, fmt.Errorf("selfupdate: asking %s for the latest release: %w", u.cfg.Repo, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return Release{}, false, fmt.Errorf("selfupdate: reading response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		// No release has been cut yet. Not an error: a freshly created repo is
		// a perfectly ordinary state for this to run against.
		return Release{}, false, nil
	default:
		return Release{}, false, fmt.Errorf("selfupdate: %s returned %s", url, resp.Status)
	}

	var payload struct {
		TagName     string    `json:"tag_name"`
		Draft       bool      `json:"draft"`
		Prerelease  bool      `json:"prerelease"`
		HTMLURL     string    `json:"html_url"`
		PublishedAt time.Time `json:"published_at"`
		Assets      []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return Release{}, false, fmt.Errorf("selfupdate: decoding release: %w", err)
	}

	if payload.Draft || payload.Prerelease {
		return Release{}, false, nil
	}

	release := Release{
		Version:     payload.TagName,
		PublishedAt: payload.PublishedAt,
		URL:         payload.HTMLURL,
	}

	for _, asset := range payload.Assets {
		switch asset.Name {
		case u.cfg.AssetName:
			release.AssetURL = asset.URL
		case "checksums.txt":
			release.ChecksumURL = asset.URL
		}
	}

	if !newer(payload.TagName, u.cfg.CurrentVersion) {
		return release, false, nil
	}

	if release.AssetURL == "" {
		return release, false, fmt.Errorf("%w: %s has no %q", ErrNoAsset, payload.TagName, u.cfg.AssetName)
	}

	return release, true, nil
}

// Apply downloads the release, verifies it against the published checksums, and
// replaces the installed binary.
//
// It returns without touching anything if the download does not verify. The
// caller carries on with the build it already has, which is the right outcome:
// a monitor running last week's code still sends alerts.
func (u *Updater) Apply(ctx context.Context, release Release) error {
	ctx, cancel := context.WithTimeout(ctx, u.cfg.Timeout)
	defer cancel()

	if release.ChecksumURL == "" {
		return fmt.Errorf("selfupdate: %s publishes no checksums.txt; refusing to install it", release.Version)
	}

	target, err := u.target()
	if err != nil {
		return err
	}

	want, err := u.expectedSum(ctx, release.ChecksumURL)
	if err != nil {
		return err
	}

	tmp, sum, err := u.download(ctx, release.AssetURL, target)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)

	if sum != want {
		return fmt.Errorf("selfupdate: %s does not match its published checksum (got %s, want %s); not installing it", release.Version, sum[:12], want[:12])
	}

	// Rename within the same directory, so it is atomic and so a running copy
	// keeps the inode it was started from.
	if err := os.Rename(tmp, target); err != nil {
		return fmt.Errorf("selfupdate: replacing %s: %w", target, err)
	}

	return nil
}

// target is the path to replace.
func (u *Updater) target() (string, error) {
	if u.cfg.ExecutablePath != "" {
		return u.cfg.ExecutablePath, nil
	}

	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("selfupdate: locating the running binary: %w", err)
	}

	// Resolve symlinks so that an update replaces the real file rather than
	// turning a deliberate symlink into a binary.
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path, nil
	}

	return resolved, nil
}

// expectedSum fetches checksums.txt and returns the digest for our asset. The
// format is sha256sum's: "<hex>  <filename>" per line.
func (u *Updater) expectedSum(ctx context.Context, url string) (string, error) {
	body, err := u.get(ctx, url, 1<<20)
	if err != nil {
		return "", fmt.Errorf("selfupdate: fetching checksums: %w", err)
	}

	for line := range strings.SplitSeq(string(body), "\n") {
		digest, name, found := strings.Cut(strings.TrimSpace(line), " ")
		if !found {
			continue
		}

		if strings.TrimSpace(name) == u.cfg.AssetName {
			return digest, nil
		}
	}

	return "", fmt.Errorf("selfupdate: checksums.txt has no entry for %q", u.cfg.AssetName)
}

// download writes the asset to a temporary file beside the target, hashing as
// it goes, and returns the path and the digest.
func (u *Updater) download(ctx context.Context, url, target string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", fmt.Errorf("selfupdate: building request: %w", err)
	}

	resp, err := u.http.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("selfupdate: downloading %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("selfupdate: downloading %s returned %s", url, resp.Status)
	}

	// The temporary file must share a filesystem with the target for the rename
	// to be atomic, so it goes in the same directory.
	tmp, err := os.CreateTemp(filepath.Dir(target), ".dmarc-monitor-update-*")
	if err != nil {
		return "", "", fmt.Errorf("selfupdate: creating a temporary file beside %s: %w", target, err)
	}

	hash := sha256.New()

	written, err := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(resp.Body, maxAsset+1))
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())

		return "", "", fmt.Errorf("selfupdate: writing the download: %w", err)
	}

	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())

		return "", "", fmt.Errorf("selfupdate: closing the download: %w", err)
	}

	if written > maxAsset {
		os.Remove(tmp.Name())

		return "", "", fmt.Errorf("selfupdate: download exceeds %d bytes", maxAsset)
	}

	// Executable before it is installed, never after: a moment where the target
	// exists but cannot be run is a moment cron would fail in.
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		os.Remove(tmp.Name())

		return "", "", fmt.Errorf("selfupdate: making the download executable: %w", err)
	}

	return tmp.Name(), hex.EncodeToString(hash.Sum(nil)), nil
}

func (u *Updater) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := u.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", url, resp.Status)
	}

	return io.ReadAll(io.LimitReader(resp.Body, limit))
}
