// Package updates fetches the public desktop version manifest (no auth).
// Fail-open: network or parse errors return ErrUnavailable; Protect must keep working.
package updates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultManifestURL is the public HTTPS endpoint (no registration).
const DefaultManifestURL = "https://denyout.com/updates/desktop.json"

// ErrUnavailable means the check failed; callers must not block the user.
var ErrUnavailable = errors.New("update check unavailable")

// Manifest is the public desktop update document.
type Manifest struct {
	Version     string `json:"version"`
	Channel     string `json:"channel,omitempty"` // stable | beta
	URL         string `json:"url"`               // download or release page
	Notes       string `json:"notes,omitempty"`
	PublishedAt string `json:"published_at,omitempty"` // RFC3339
}

// Result is a comparison of local vs remote.
type Result struct {
	Newer   bool
	Local   string
	Remote  Manifest
	Checked time.Time
}

// ParseManifest decodes JSON bytes.
func ParseManifest(data []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	m.Version = strings.TrimSpace(m.Version)
	m.URL = strings.TrimSpace(m.URL)
	if m.Version == "" || m.URL == "" {
		return Manifest{}, fmt.Errorf("%w: missing version or url", ErrUnavailable)
	}
	return m, nil
}

// Fetch downloads the manifest. No auth headers. ctx cancels the request.
func Fetch(ctx context.Context, client *http.Client, manifestURL string) (Manifest, error) {
	if manifestURL == "" {
		manifestURL = DefaultManifestURL
	}
	if client == nil {
		client = &http.Client{Timeout: 12 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	req.Header.Set("Accept", "application/json")
	// Optional product UA only — not a device identity.
	req.Header.Set("User-Agent", "denyout-update-check")

	res, err := client.Do(req)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if res.StatusCode != http.StatusOK {
		return Manifest{}, fmt.Errorf("%w: HTTP %d", ErrUnavailable, res.StatusCode)
	}
	return ParseManifest(body)
}

// Check compares localVersion to the remote manifest.
// Non-semver / empty / "dev" local versions never report Newer (fail-open UX).
func Check(ctx context.Context, client *http.Client, manifestURL, localVersion string) (Result, error) {
	m, err := Fetch(ctx, client, manifestURL)
	if err != nil {
		return Result{}, err
	}
	out := Result{Local: localVersion, Remote: m, Checked: time.Now().UTC()}
	out.Newer = IsNewer(m.Version, localVersion)
	return out, nil
}

// IsNewer reports whether remote is a higher semver-like version than local.
func IsNewer(remote, local string) bool {
	r := normalizeVer(remote)
	l := normalizeVer(local)
	if r == "" || l == "" || l == "dev" {
		return false
	}
	rp := verParts(r)
	lp := verParts(l)
	n := len(rp)
	if len(lp) > n {
		n = len(lp)
	}
	for i := 0; i < n; i++ {
		rv, lv := 0, 0
		if i < len(rp) {
			rv = rp[i]
		}
		if i < len(lp) {
			lv = lp[i]
		}
		if rv > lv {
			return true
		}
		if rv < lv {
			return false
		}
	}
	return false
}

func normalizeVer(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "v")
	// Drop pre-release / build metadata for MVP compare.
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	return s
}

func verParts(s string) []int {
	bits := strings.Split(s, ".")
	out := make([]int, 0, len(bits))
	for _, b := range bits {
		n, err := strconv.Atoi(b)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}
