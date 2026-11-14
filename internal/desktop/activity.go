package desktop

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/notify"
)

func (a *App) activityPageURL() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.controlURL == "" {
		return ""
	}
	return strings.TrimRight(a.controlURL, "/") + "/activity"
}

func (a *App) registerActivityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/activity", a.handleActivityPage)
	mux.HandleFunc("/api/desktop/status", a.handleDesktopStatus)
	mux.HandleFunc("/api/desktop/denials", a.handleDesktopDenials)
	mux.HandleFunc("/api/desktop/mode", a.handleDesktopMode)
	mux.HandleFunc("/api/desktop/settings", a.handleDesktopSettings)
}

func (a *App) handleActivityPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b, err := staticFS.ReadFile("static/activity.html")
	if err != nil {
		http.Error(w, "activity page missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func (a *App) handleDesktopStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mode := a.currentMode()
	a.mu.Lock()
	st := a.state
	status := a.status
	lastDeny := a.lastDeny
	ver := a.opts.Version
	if ver == "" {
		ver = "dev"
	}
	a.mu.Unlock()

	writeJSON(w, map[string]any{
		"mode":              mode,
		"mode_label":        modeLabel(mode),
		"protection_on":     st.ProtectionOn || mode != ModeOff,
		"status":            status,
		"ask_mode":          st.AskMode,
		"notify":            st.Notify,
		"policy_profile":    normalizePolicyProfile(st.PolicyProfile),
		"version":           ver,
		"last_deny_host":    lastDeny,
		"last_deny_summary": st.LastDenySummary,
		"audit_path":        AuditLogPath(),
		"diagnostics_dir":   LogDir(),
		"hints":             a.activityHints(),
	})
}

func (a *App) activityHints() []string {
	var hints []string
	if !certutilAvailable() {
		hints = append(hints, "Chrome/Chromium NSS trust needs certutil (e.g. apt install libnss3-tools). Without it, browsers may show SSL warnings for intercepted HTTPS.")
	}
	if !clipboardAvailable() {
		hints = append(hints, "Clipboard copy needs wl-copy or xclip (e.g. apt install wl-clipboard). Copy last error falls back to showing text in a dialog.")
	}
	return hints
}

func certutilAvailable() bool {
	_, err := exec.LookPath("certutil")
	return err == nil
}

func clipboardAvailable() bool {
	switch runtime.GOOS {
	case "darwin", "windows":
		return true
	default:
		for _, bin := range []string{"wl-copy", "xclip", "xsel"} {
			if _, err := exec.LookPath(bin); err == nil {
				return true
			}
		}
		return false
	}
}

func (a *App) handleDesktopDenials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := 50
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
			if limit > 500 {
				limit = 500
			}
		}
	}
	events, err := audit.RecentDenials(AuditLogPath(), limit)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if events == nil {
		events = []audit.Event{}
	}
	writeJSON(w, map[string]any{"events": events})
}

func (a *App) handleDesktopMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	mode := strings.ToLower(strings.TrimSpace(body.Mode))
	var err error
	switch mode {
	case ModeComputer:
		err = a.enableComputerFromTray()
	case ModeSession:
		err = a.enableSessionFromTray()
	case ModeOff:
		a.stopProtection()
	default:
		writeJSONErr(w, http.StatusBadRequest, "mode must be computer, session, or off")
		return
	}
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "mode": a.currentMode()})
}

func (a *App) handleDesktopSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		AskMode       *bool   `json:"ask_mode"`
		Notify        *bool   `json:"notify"`
		PolicyProfile *string `json:"policy_profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	a.mu.Lock()
	if body.AskMode != nil {
		a.state.AskMode = *body.AskMode
	}
	if body.Notify != nil {
		a.state.Notify = *body.Notify
		notify.SetEnabled(a.state.Notify)
	}
	profileChanged := false
	if body.PolicyProfile != nil {
		np := normalizePolicyProfile(*body.PolicyProfile)
		if normalizePolicyProfile(a.state.PolicyProfile) != np {
			a.state.PolicyProfile = np
			profileChanged = true
		}
	}
	st := a.state
	wasOn := a.proxyd != nil || a.session != nil
	askChanged := body.AskMode != nil
	a.mu.Unlock()
	_ = SaveState(st)
	if wasOn && (askChanged || profileChanged) {
		a.restartActiveProtector()
	}
	writeJSON(w, map[string]any{
		"ok":             true,
		"ask_mode":       st.AskMode,
		"notify":         st.Notify,
		"policy_profile": normalizePolicyProfile(st.PolicyProfile),
	})
}

func writeJSONErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
