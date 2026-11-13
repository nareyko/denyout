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
	Version    string
	ForceSetup bool
	NoTray     bool
	NoOpen     bool
	Listen     string // wizard HTTP listen; default 127.0.0.1:0
}

// App is the non-technical desktop entry (wizard + tray + hostguard).
type App struct {
	opts Options

	mu       sync.Mutex
	state    State
	lastDeny string
	status   string
	protect  *exec.Cmd   // advanced process wrap
	session  *run.Session // computer mode proxy
}

// Run starts the desktop experience and blocks until quit.
func Run(ctx context.Context, opts Options) error {
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:0"
	}
	a := &App{opts: opts, state: LoadState(), status: "Off"}
	notify.SetEnabled(a.state.Notify)

	wizardURL, err := a.startWizardServer(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "denyout desktop: setup UI %s (localhost only)\n", wizardURL)

	needSetup := opts.ForceSetup || !a.state.SetupDone
	if needSetup && !opts.NoOpen {
		openBrowser(wizardURL)
	}

	if opts.NoTray {
		fmt.Fprintln(os.Stderr, "denyout desktop: tray disabled (--no-tray); press Ctrl+C to quit")
		<-ctx.Done()
		a.stopComputer()
		a.stopProtect()
		return nil
	}

	return a.runTray(ctx, wizardURL)
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
		"setup_done":        a.state.SetupDone,
		"status":            a.status,
		"last_deny":         a.lastDeny,
		"notify":            a.state.Notify,
		"ask_mode":          a.state.AskMode,
		"computer_enabled":  a.state.ComputerEnabled,
		"agent":             a.state.PreferredAgent,
		"always_allow":      a.state.AlwaysAllowHosts,
		"version":           a.opts.Version,
	})
}

func (a *App) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Notify  bool `json:"notify"`
		AskMode bool `json:"ask_mode"`
		Skip    bool `json:"skip"`
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
		Notify  *bool `json:"notify"`
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
	wasOn := a.session != nil
	a.mu.Unlock()
	notify.SetEnabled(st.Notify)
	if err := SaveState(st); err != nil {
		writeErr(w, err, 500)
		return
	}
	if wasOn && body.AskMode != nil {
		a.stopComputer()
		if err := a.startComputer(); err != nil {
			writeErr(w, err, 500)
			return
		}
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
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, err, 400)
		return
	}
	if body.Enabled {
		if err := a.startComputer(); err != nil {
			writeErr(w, err, 500)
			return
		}
	} else {
		a.stopComputer()
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
		Host  string `json:"host"`
		Once  bool   `json:"once"`
		Always bool  `json:"always"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, err, 400)
		return
	}
	if body.Always || !body.Once {
		if err := a.allowHostAlways(strings.TrimSpace(body.Host)); err != nil {
			writeErr(w, err, 500)
			return
		}
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) handleProtect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Agent         string `json:"agent"`
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
		return fmt.Errorf("a protected agent is already running — stop it from the tray first")
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
