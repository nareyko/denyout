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
)

//go:embed static/*
var staticFS embed.FS

//go:embed icon.png
var iconPNG []byte

// Options for denyout desktop.
type Options struct {
	ConfigPath string
	Version    string
	ForceSetup bool
	NoTray     bool
	NoOpen     bool
	Listen     string // wizard HTTP listen; default 127.0.0.1:0
}

// App is the non-technical desktop entry (wizard + tray + notifications).
type App struct {
	opts Options

	mu       sync.Mutex
	state    State
	lastDeny string
	status   string
	protect  *exec.Cmd
}

// Run starts the desktop experience and blocks until quit.
func Run(ctx context.Context, opts Options) error {
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:0"
	}
	a := &App{opts: opts, state: LoadState(), status: "Idle"}
	notify.SetEnabled(a.state.Notify)

	wizardURL, err := a.startWizardServer(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "denyout desktop: setup UI %s (localhost only)\n", wizardURL)

	needSetup := opts.ForceSetup || !a.state.SetupDone
	if needSetup && !opts.NoOpen {
		openBrowser(wizardURL)
	} else if !opts.NoOpen && !a.state.SetupDone {
		openBrowser(wizardURL)
	}

	if opts.NoTray {
		fmt.Fprintln(os.Stderr, "denyout desktop: tray disabled (--no-tray); press Ctrl+C to quit")
		<-ctx.Done()
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
	mux.HandleFunc("/api/protect", a.handleProtect)
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
		"status":     a.status,
		"last_deny":  a.lastDeny,
		"notify":     a.state.Notify,
		"agent":      a.state.PreferredAgent,
	})
}

func (a *App) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Agent         string `json:"agent"`
		CustomCommand string `json:"custom_command"`
		Notify        bool   `json:"notify"`
		Skip          bool   `json:"skip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, err, 400)
		return
	}
	a.mu.Lock()
	a.state.SetupDone = true
	a.state.Notify = body.Notify
	if !body.Skip {
		a.state.PreferredAgent = body.Agent
		a.state.CustomCommand = strings.TrimSpace(body.CustomCommand)
	} else if a.state.PreferredAgent == "" {
		a.state.PreferredAgent = "shell"
	}
	st := a.state
	a.mu.Unlock()
	notify.SetEnabled(st.Notify)
	if err := SaveState(st); err != nil {
		writeErr(w, err, 500)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *App) handleProtect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
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
			return nil, fmt.Errorf("set a custom command in setup first")
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
	// Minimal split on spaces; enough for MVP custom commands.
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
	a.status = "Starting…"
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
		a.mu.Lock()
		a.status = "Idle"
		a.mu.Unlock()
		return err
	}
	a.mu.Lock()
	a.protect = cmd
	a.status = "Protected"
	a.mu.Unlock()

	go func() {
		_ = cmd.Wait()
		a.mu.Lock()
		a.protect = nil
		a.status = "Idle"
		a.mu.Unlock()
	}()
	return nil
}

func (a *App) stopProtect() {
	a.mu.Lock()
	cmd := a.protect
	a.protect = nil
	a.status = "Idle"
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
