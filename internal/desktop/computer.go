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
		return fmt.Errorf("Protect this computer is already on")
	}
	ask := a.state.AskMode
	wizard := a.wizardURL
	a.status = "Starting…"
	a.mu.Unlock()

	// Reserve a free local port for the transparent proxy.
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
	if wizard != "" {
		// Optional --web-ui only; native Ask uses dialogs / notify-send actions.
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

	// Wait until the proxyd is listening.
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
	a.state.ComputerEnabled = true
	a.status = "Protecting computer"
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
			if a.status == "Protecting computer" {
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
			// Prefer native dialog; "" = no toolkit → notify-send / optional web allow page.
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
	a.mu.Lock()
	cmd := a.proxyd
	port := a.proxyPort
	sess := a.session
	a.proxyd = nil
	a.proxyPort = 0
	a.session = nil
	a.state.ComputerEnabled = false
	a.status = "Off"
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
	if sess != nil {
		_ = sess.Stop()
	}
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
		return fmt.Errorf("Protect this computer is off")
	}
	if sess != nil {
		sess.AllowHost(host, "user_once")
		return nil
	}
	// proxyd subprocess: persist as Always for this session via state + restart
	// Minimal: treat once like always for subprocess mode until IPC exists.
	return a.allowHostAlways(host)
}

func (a *App) allowHostAlways(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("empty host")
	}
	a.mu.Lock()
	found := false
	for _, h := range a.state.AlwaysAllowHosts {
		if h == host {
			found = true
			break
		}
	}
	if !found {
		a.state.AlwaysAllowHosts = append(a.state.AlwaysAllowHosts, host)
	}
	st := a.state
	sess := a.session
	wasOn := a.proxyd != nil || sess != nil
	a.mu.Unlock()
	if err := SaveState(st); err != nil {
		return err
	}
	if sess != nil {
		sess.AllowHost(host, "user_always")
		return nil
	}
	if wasOn {
		a.stopComputer()
		return a.startComputer()
	}
	return nil
}
