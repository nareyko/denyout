package desktop

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/nareyko/denyout/internal/notify"
	"github.com/nareyko/denyout/internal/run"
	"github.com/nareyko/denyout/internal/threatlists"
)

//go:embed static/*
var staticFS embed.FS

//go:embed icon.png
var iconPNG []byte

//go:embed icon-on.png
var iconOnPNG []byte

//go:embed icon-idle.png
var iconIdlePNG []byte

//go:embed icon-alert.png
var iconAlertPNG []byte

// Keep default icon referenced for older tray paths / tests.
var _ = iconPNG

// Options for denyout desktop.
type Options struct {
	ConfigPath string
	Version string
	ForceSetup bool
	NoTray bool
	NoOpen bool
	WebUI bool // optional localhost settings UI (advanced / tests only)
	Listen string // web UI listen when WebUI; default 127.0.0.1:0
	ControlListen string // activity/control listen; default 127.0.0.1:0 (tests may pin)
	// OpenUI is called when tray wants the modern window (Wails). route: home|activity|profiles|settings|problems|""
	OpenUI func(route string)
	// SkipNativeYourSetup skips zenity Your setup (Wails shows in-window modal instead).
	SkipNativeYourSetup bool
}

// App is the non-technical desktop entry (tray + hostguard / session proxy).
type App struct {
	opts Options

	mu sync.Mutex
	state State
	lastDeny string
	status string
	protect *exec.Cmd // advanced process wrap
	session *run.Session // session-mode in-process proxy
	proxyd *exec.Cmd // computer-mode transparent proxy subprocess
	proxyPort int
	wizardURL string // only set when WebUI is enabled
	controlURL string // Ask IPC for proxyd
	asks *askFlight
	wraps map[string]*wrapProc
	threats *threatlists.Store // Book C cache (shared across Protect restarts)
	updateHTTP *http.Client // optional; tests inject; nil -> default
	accountHTTP *http.Client // optional; tests inject for account API
}

func applyNotifyPrefs(st State) {
	lvl := strings.TrimSpace(st.NotifyLevel)
	if lvl == "" {
		if st.Notify {
			lvl = "normal"
		} else {
			lvl = "quiet"
		}
	}
	notify.SetLevel(lvl)
}

// NewApp constructs a desktop app from options and persisted state.
func NewApp(opts Options) *App {
	a := &App{opts: opts, state: LoadState(), status: "Off", wraps: map[string]*wrapProc{}, asks: newAskFlight()}
	applyNotifyPrefs(a.state)
	if a.state.LastDenyHost != "" {
		a.lastDeny = a.state.LastDenyHost
	}
	return a
}

// Bootstrap starts control IPC, first-run / restore. Does not block on tray.
func (a *App) Bootstrap(ctx context.Context) error {
	if _, err := a.startControlServer(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "denyout desktop: control IPC server: %v\n", err)
	}

	a.maybePromptCrashLeftovers()

	needSetup := a.opts.ForceSetup || !a.state.SetupDone
	if needSetup && a.opts.WebUI {
		// web wizard handles setup
	} else if needSetup && !a.opts.WebUI {
		if a.opts.ForceSetup {
			a.mu.Lock()
			a.state.SetupDone = true
			a.state.PolicyProfile = PolicyProfileBrowse
			a.state.AskMode = false
			a.state.UXv2Migrated = true
			if !a.state.Notify {
				a.state.Notify = true
			}
			st := a.state
			a.mu.Unlock()
			_ = SaveState(st)
			notify.SetEnabled(true)
		} else {
			a.runFirstRunWizard()
		}
	}

	a.maybeMigrateUXv2()
	a.maybeNotNowNudge()
	a.maybeLearningNudge()
	a.startTimedRulesWorker(ctx)

	if a.opts.WebUI {
		opts := a.opts
		if opts.Listen == "" {
			opts.Listen = "127.0.0.1:0"
		}
		a.opts = opts
		wizardURL, err := a.startWizardServer(ctx)
		if err != nil {
			return err
		}
		a.wizardURL = wizardURL
		fmt.Fprintf(os.Stderr, "denyout desktop: optional web UI %s (--web-ui)\n", wizardURL)
		if needSetup && !opts.NoOpen {
			openBrowser(wizardURL)
		}
	}

	// Restore Computer after login; never silently fall back to Session.
	if a.state.SetupDone && (!a.opts.WebUI || a.state.ProtectionOn) {
		a.restoreProtection()
	}

	// install.sh / --install skips first-run wizard; still show Your setup once (GUI tray only).
	if a.state.SetupDone && !a.state.YourSetupShown && !a.opts.WebUI && !a.opts.NoTray && !a.opts.SkipNativeYourSetup {
		mode := "off"
		if a.currentMode() == ModeComputer && normalizePolicyProfile(a.state.PolicyProfile) == PolicyProfileBrowse {
			mode = "safe"
		}
		a.showYourSetup(mode)
	}
	return nil
}

// RequestOpenUI opens the Wails (or other) window on route.
func (a *App) RequestOpenUI(route string) {
	if a.opts.OpenUI != nil {
		a.opts.OpenUI(route)
		return
	}
	// CLI desktop fallback: native dialogs.
	switch route {
	case "problems":
		a.helpAndProblems()
	case "home", "":
		// Prefer activity list as native "home" stand-in when no Wails window.
		a.nativeShowActivity()
	default:
		a.nativeShowActivity()
	}
}

// Run starts the desktop experience and blocks until quit.
func Run(ctx context.Context, opts Options) error {
	a := NewApp(opts)
	if err := a.Bootstrap(ctx); err != nil {
		return err
	}

	if opts.NoTray {
		fmt.Fprintln(os.Stderr, "denyout desktop: tray disabled (--no-tray). Press Ctrl+C to quit")
		<-ctx.Done()
		a.stopAll()
		a.stopAllWrapsOpts("", true)
		a.stopProtect()
		return nil
	}

	return a.runTray(ctx)
}

func (a *App) startWizardServer(ctx context.Context) (string, error) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return "", err
	}
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/setup", a.handleSetup)
	mux.HandleFunc("/api/settings", a.handleSettings)
	mux.HandleFunc("/api/protect", a.handleProtect)
	mux.HandleFunc("/api/computer", a.handleComputer)
	mux.HandleFunc("/api/allow", a.handleAllow)
	mux.HandleFunc("/api/status", a.handleStatus)

	ln, err := net.Listen("tcp", a.opts.Listen)
	if err != nil {
		return "", err
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()
	go func() { _ = srv.Serve(ln) }()
	return "http://" + ln.Addr().String() + "/", nil
}

func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	writeJSON(w, map[string]any{
		"setup_done": a.state.SetupDone,
		"status": a.status,
		"last_deny": a.lastDeny,
		"notify": a.state.Notify,
		"ask_mode": a.state.AskMode,
		"scope": a.state.Scope,
		"protection_on": a.state.ProtectionOn,
		"computer_enabled": a.state.ComputerEnabled,
		"computer_available": a.state.ComputerAvailable,
		"agent": a.state.PreferredAgent,
		"always_allow": a.state.AlwaysAllowHosts,
		"version": a.opts.Version,
		"audit_log": AuditLogPath(),
	})
}

func (a *App) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Notify bool `json:"notify"`
		AskMode bool `json:"ask_mode"`
		Skip bool `json:"skip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, err, 400)
		return
	}
	a.mu.Lock()
	a.state.SetupDone = true
	a.state.Notify = body.Notify
	a.state.AskMode = body.AskMode
	st := a.state
	a.mu.Unlock()
	notify.SetEnabled(st.Notify)
	if err := SaveState(st); err != nil {
		writeErr(w, err, 500)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Notify *bool `json:"notify"`
		AskMode *bool `json:"ask_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, err, 400)
		return
	}
	a.mu.Lock()
	if body.Notify != nil {
		a.state.Notify = *body.Notify
	}
	if body.AskMode != nil {
		a.state.AskMode = *body.AskMode
	}
	st := a.state
	wasOn := a.proxyd != nil || a.session != nil
	a.mu.Unlock()
	notify.SetEnabled(st.Notify)
	if err := SaveState(st); err != nil {
		writeErr(w, err, 500)
		return
	}
	if wasOn && body.AskMode != nil {
		a.restartActiveProtector()
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) handleComputer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
		Scope string `json:"scope"` // computer | session | off
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, err, 400)
		return
	}
	switch {
	case body.Scope == ScopeSession || (body.Enabled && body.Scope == ScopeSession):
		_ = a.enableSessionFromTray()
	case body.Scope == "off" || (!body.Enabled && body.Scope == ""):
		a.stopProtectionFromTray()
	case body.Enabled || body.Scope == ScopeComputer:
		_ = a.enableComputerFromTray()
	}
	a.mu.Lock()
	st := a.status
	a.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true, "status": st})
}

func (a *App) handleAllow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Host string `json:"host"`
		Once bool `json:"once"`
		Always bool `json:"always"`
		Deny bool `json:"deny"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, err, 400)
		return
	}
	host := strings.TrimSpace(body.Host)
	switch {
	case body.Deny:
		writeJSON(w, map[string]any{"ok": true, "action": "deny"})
	case body.Always:
		if err := a.allowHostAlways(host); err != nil {
			writeErr(w, err, 500)
			return
		}
		writeJSON(w, map[string]any{"ok": true, "action": "always"})
	case body.Once:
		if err := a.allowHostOnce(host); err != nil {
			writeErr(w, err, 500)
			return
		}
		writeJSON(w, map[string]any{"ok": true, "action": "once"})
	default:
		writeErr(w, fmt.Errorf("specify once, always, or deny"), 400)
	}
}

func (a *App) handleProtect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Agent string `json:"agent"`
		CustomCommand string `json:"custom_command"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Agent != "" {
		a.mu.Lock()
		a.state.PreferredAgent = body.Agent
		a.state.CustomCommand = strings.TrimSpace(body.CustomCommand)
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
	}
	if err := a.startProtect(); err != nil {
		writeErr(w, err, 500)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "status": "starting"})
}

func (a *App) agentCommand() ([]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch a.state.PreferredAgent {
	case "claude":
		return []string{"claude"}, nil
	case "cursor":
		return []string{"agent"}, nil
	case "custom":
		if a.state.CustomCommand == "" {
			return nil, fmt.Errorf("set a custom command in Advanced first")
		}
		return splitCommand(a.state.CustomCommand), nil
	default:
		shell := os.Getenv("SHELL")
		if shell == "" {
			if runtime.GOOS == "windows" {
				shell = "cmd.exe"
			} else {
				shell = "/bin/sh"
			}
		}
		return []string{shell}, nil
	}
}

func splitCommand(s string) []string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return []string{s}
	}
	return fields
}

func (a *App) startProtect() error {
	cmdArgs, err := a.agentCommand()
	if err != nil {
		return err
	}
	a.mu.Lock()
	if a.protect != nil && a.protect.Process != nil {
		a.mu.Unlock()
		return fmt.Errorf("a protected agent is already running - stop it from the tray first")
	}
	a.mu.Unlock()

	self, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"run"}
	if a.opts.ConfigPath != "" {
		args = append(args, "--config", a.opts.ConfigPath)
	}
	args = append(args, "--")
	args = append(args, cmdArgs...)

	cmd := exec.Command(self, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "DENYOUT_DESKTOP_NOTIFY=1")
	if err := cmd.Start(); err != nil {
		return err
	}
	a.mu.Lock()
	a.protect = cmd
	a.mu.Unlock()

	go func() {
		_ = cmd.Wait()
		a.mu.Lock()
		a.protect = nil
		a.mu.Unlock()
	}()
	return nil
}

func (a *App) stopProtect() {
	a.mu.Lock()
	cmd := a.protect
	a.protect = nil
	a.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func openBrowser(url string) {
	time.Sleep(250 * time.Millisecond)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
