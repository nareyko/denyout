package desktop

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/updates"
)

// UpdateCheckView is the Settings / Home payload for program updates (no account).
type UpdateCheckView struct {
	Newer         bool   `json:"newer"`
	Local         string `json:"local"`
	RemoteVersion string `json:"remote_version,omitempty"`
	URL           string `json:"url,omitempty"`
	Notes         string `json:"notes,omitempty"`
	Message       string `json:"message"`
	CheckedAt     string `json:"checked_at,omitempty"`
}

// UICheckForUpdates fetches the public manifest and updates persisted tip fields.
// Fail-open: network errors return a soft message, never an account prompt.
func (a *App) UICheckForUpdates() (UpdateCheckView, error) {
	if a == nil {
		return UpdateCheckView{Message: "DenyOut is not ready."}, nil
	}
	manifestURL := strings.TrimSpace(os.Getenv("DENYOUT_UPDATE_MANIFEST_URL"))
	a.mu.Lock()
	local := a.opts.Version
	if u := strings.TrimSpace(a.state.UpdateManifestURL); u != "" {
		manifestURL = u
	}
	client := a.updateHTTP
	a.mu.Unlock()
	if client == nil {
		client = &http.Client{Timeout: 12 * time.Second}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := updates.Check(ctx, client, manifestURL, local)
	checked := time.Now().UTC().Format(time.RFC3339)

	if err != nil {
		msg := "Could not check for updates right now. Protect still works."
		if errors.Is(err, updates.ErrUnavailable) {
			// keep soft copy
		}
		a.mu.Lock()
		a.state.UpdateCheckedAt = checked
		// Do not clear a previously known available update on transient failure.
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		return UpdateCheckView{
			Local:     local,
			Message:   msg,
			CheckedAt: checked,
		}, nil
	}

	a.mu.Lock()
	a.state.UpdateCheckedAt = checked
	if res.Newer {
		a.state.UpdateAvailableVersion = res.Remote.Version
		a.state.UpdateAvailableURL = res.Remote.URL
		a.state.UpdateAvailableNotes = res.Remote.Notes
	} else {
		a.state.UpdateAvailableVersion = ""
		a.state.UpdateAvailableURL = ""
		a.state.UpdateAvailableNotes = ""
	}
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)

	out := UpdateCheckView{
		Newer:         res.Newer,
		Local:         local,
		RemoteVersion: res.Remote.Version,
		URL:           res.Remote.URL,
		Notes:         res.Remote.Notes,
		CheckedAt:     checked,
	}
	if res.Newer {
		out.Message = "A newer DenyOut is available. Open the release link when you are ready — no sign-in needed."
	} else {
		out.Message = "You are up to date."
	}
	return out, nil
}

// updateTipLocked returns snapshot fields for an available update (caller holds a.mu).
func updateTipLocked(a *App) (newer bool, ver, url, notes string) {
	ver = strings.TrimSpace(a.state.UpdateAvailableVersion)
	if ver == "" {
		return false, "", "", ""
	}
	if !updates.IsNewer(ver, a.opts.Version) {
		return false, "", "", ""
	}
	return true, ver, a.state.UpdateAvailableURL, a.state.UpdateAvailableNotes
}

// UIOpenUpdateURL opens the release link from the last successful newer check.
func (a *App) UIOpenUpdateURL() error {
	a.mu.Lock()
	u := strings.TrimSpace(a.state.UpdateAvailableURL)
	a.mu.Unlock()
	if u == "" {
		return errors.New("no update link yet — check for updates first")
	}
	openBrowser(u)
	return nil
}
