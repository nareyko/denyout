package desktop

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/notify"
	"github.com/nareyko/denyout/internal/proxy"
)

func (a *App) startComputer() error {
	a.mu.Lock()
	if a.session != nil || a.proxyd != nil {
		a.mu.Unlock()
		return fmt.Errorf("protection is already on")
	}
	ask := a.state.AskMode
	wizard := a.wizardURL
	control := a.controlURL
	a.status = "Starting…"
	a.mu.Unlock()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		a.setStatus("Error")
		return err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	caDir := CADir()
	if _, err := proxy.LoadOrCreatePersistentCA(caDir); err != nil {
		a.setStatus("Error")
		return err
	}
	caPath := caDir + "/ca.crt"

	uid, _ := hostguard.CurrentUID()
	if err := hostguard.ElevateApply(port, caPath, uid); err != nil {
		a.setStatus("Needs admin")
		a.mu.Lock()
		a.state.ComputerAvailable = false
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
		return err
	}

	self, err := os.Executable()
	if err != nil {
		_ = hostguard.ElevateRemove(port, uid)
		a.setStatus("Error")
		return err
	}
	args := []string{
		"hostctl", "proxyd",
		"--port", strconv.Itoa(port),
		"--ca-dir", caDir,
	}
	if ask {
		args = append(args, "--ask")
	}
	if control != "" {
		args = append(args, "--control-url", control)
	}
	if wizard != "" {
		args = append(args, "--allow-base", strings.TrimRight(wizard, "/"))
	}
	cmd := exec.Command(self, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	env := os.Environ()
	a.mu.Lock()
	if len(a.state.AlwaysAllowHosts) > 0 {
		env = append(env, "DENYOUT_ALWAYS_ALLOW="+strings.Join(a.state.AlwaysAllowHosts, ","))
	}
	a.mu.Unlock()
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		_ = hostguard.ElevateRemove(port, uid)
		a.setStatus("Error")
		return err
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	a.mu.Lock()
	a.proxyd = cmd
	a.proxyPort = port
	a.state.Scope = ScopeComputer
	a.state.ProtectionOn = true
	a.state.ComputerEnabled = true
	a.state.ComputerAvailable = true
	a.status = "Computer"
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)

	go func() {
		_ = cmd.Wait()
		a.mu.Lock()
		if a.proxyd == cmd {
			a.proxyd = nil
			a.proxyPort = 0
			a.state.ComputerEnabled = false
			if a.status == "Computer" {
				a.status = "Off"
			}
		}
		a.mu.Unlock()
	}()
	return nil
}

func (a *App) onComputerDeny(host string, reasons []string, wizard string) {
	a.mu.Lock()
	a.lastDeny = host
	a.state.LastDenyHost = host
	a.state.LastDenySummary = notify.HumanReasons(reasons)
	ask := a.state.AskMode
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)

	hostNotAllowed := false
	for _, r := range reasons {
		if r == "host_not_allowed" {
			hostNotAllowed = true
			break
		}
	}
	if ask && hostNotAllowed {
		go func() {
			switch nativeAllowDialog(host) {
			case "once":
				_ = a.allowHostOnce(host)
				return
			case "always":
				_ = a.allowHostAlways(host)
				return
			case "deny":
				return
			}
			allowURL := ""
			if wizard != "" {
				allowURL = strings.TrimRight(wizard, "/") + "/allow.html?host=" + url.QueryEscape(host)
			}
			notify.Ask(notify.AskOptions{
				Host:    host,
				OpenURL: allowURL,
				OnAction: func(h string, act notify.AskAction) {
					switch act {
					case notify.AskOnce:
						_ = a.allowHostOnce(h)
					case notify.AskAlways:
						_ = a.allowHostAlways(h)
					}
				},
			})
		}()
		return
	}
	notify.Deny(host, reasons)
}

func (a *App) stopComputer() {
	a.stopComputerKeep(false)
}

func (a *App) stopComputerKeep(keepRestore bool) {
	a.mu.Lock()
	cmd := a.proxyd
	port := a.proxyPort
	a.proxyd = nil
	a.proxyPort = 0
	a.state.ComputerEnabled = false
	if !keepRestore && a.state.Scope == ScopeComputer {
		a.state.ProtectionOn = false
	}
	if a.session == nil {
		a.status = "Off"
	}
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)

	if port > 0 {
		uid, _ := hostguard.CurrentUID()
		_ = hostguard.ElevateRemove(port, uid)
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			_, _ = cmd.Process.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = cmd.Process.Kill()
		}
	}
}

func (a *App) stopAll() {
	a.stopComputerKeep(true)
	a.stopSessionKeep(true)
	a.setStatus("Off")
}

func (a *App) stopProtection() {
	a.stopComputerKeep(false)
	a.stopSession()
	a.mu.Lock()
	a.state.ProtectionOn = false
	a.state.ComputerEnabled = false
	a.status = "Off"
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
}

func (a *App) setStatus(s string) {
	a.mu.Lock()
	a.status = s
	a.mu.Unlock()
}

func (a *App) allowHostOnce(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("empty host")
	}
	a.mu.Lock()
	sess := a.session
	on := a.proxyd != nil || sess != nil
	a.mu.Unlock()
	if !on {
		return fmt.Errorf("protection is off")
	}
	if sess != nil {
		sess.AllowHost(host, "user_once")
		return nil
	}
	// proxyd: once without IPC to live engine → persist + restart
	return a.allowHostAlways(host)
}

func (a *App) allowHostAlways(host string) error {
	if err := a.persistAlwaysHost(host); err != nil {
		return err
	}
	a.mu.Lock()
	sess := a.session
	wasProxy := a.proxyd != nil
	scope := a.state.Scope
	a.mu.Unlock()
	if sess != nil {
		return nil
	}
	if wasProxy {
		a.stopComputerKeep(true)
		return a.startComputer()
	}
	_ = scope
	return nil
}

func (a *App) enableComputerFromTray() {
	a.stopSession()
	a.mu.Lock()
	a.state.ComputerAvailable = true // user explicitly retries
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	if err := a.startComputer(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout desktop: %v\n", err)
		a.setStatus("Needs admin")
		notify.Info("DenyOut", "Admin approval failed. Staying in Session mode.")
		_ = a.startSession()
		return
	}
	notify.Info("DenyOut", "Protect whole computer is on.")
}

func (a *App) enableSessionFromTray() {
	a.stopComputerKeep(false)
	if err := a.startSession(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout desktop: %v\n", err)
		a.setStatus("Error")
		return
	}
	notify.Info("DenyOut", "Session mode: apps that use system proxy. Browsers may ignore it.")
}

func (a *App) restartActiveProtector() {
	a.mu.Lock()
	scope := a.state.Scope
	on := a.proxyd != nil || a.session != nil
	a.mu.Unlock()
	if !on {
		return
	}
	a.stopAll()
	a.mu.Lock()
	a.state.ProtectionOn = true
	a.state.Scope = scope
	a.mu.Unlock()
	switch scope {
	case ScopeComputer:
		if err := a.startComputer(); err != nil {
			_ = a.startSession()
		}
	default:
		_ = a.startSession()
	}
}

func (a *App) restoreProtection() {
	a.mu.Lock()
	on := a.state.ProtectionOn || a.state.ComputerEnabled
	scope := a.state.Scope
	a.mu.Unlock()
	if !on {
		return
	}
	if scope == "" {
		scope = ScopeComputer
	}
	switch scope {
	case ScopeComputer:
		if err := a.startComputer(); err != nil {
			fmt.Fprintf(os.Stderr, "denyout desktop: restore computer failed: %v — session mode\n", err)
			a.mu.Lock()
			a.state.ComputerAvailable = false
			a.mu.Unlock()
			_ = a.startSession()
		}
	case ScopeSession:
		if err := a.startSession(); err != nil {
			fmt.Fprintf(os.Stderr, "denyout desktop: restore session failed: %v\n", err)
		}
	}
}
