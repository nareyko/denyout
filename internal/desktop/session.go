package desktop

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nareyko/denyout/internal/notify"
	"github.com/nareyko/denyout/internal/proxy"
	"github.com/nareyko/denyout/internal/run"
)

func (a *App) startSession() error {
	a.mu.Lock()
	if a.session != nil || a.proxyd != nil {
		a.mu.Unlock()
		return fmt.Errorf("protection is already on")
	}
	a.status = "Starting..."
	ver := a.opts.Version
	a.mu.Unlock()

	caDir := CADir()
	if _, err := proxy.LoadOrCreatePersistentCA(caDir); err != nil {
		a.setStatus("Error")
		return err
	}

	cfg, err := a.desktopPolicyConfig()
	if err != nil {
		a.setStatus("Error")
		return err
	}

	a.mu.Lock()
	profile := normalizePolicyProfile(a.state.PolicyProfile)
	a.mu.Unlock()
	threats := a.ensureThreatStore(true)
	sess, err := run.StartSession(run.SessionOptions{
		Config: cfg,
		TLSMode: proxy.TLSIntercept,
		Version: ver,
		CADir: caDir,
		PersistCA: true,
		PolicyProfile: profile,
		Process: "desktop-session",
		Threats: threats,
		OnDeny: func(host string, reasons []string, redactedURL string) {
			a.onSessionDeny(host, reasons, redactedURL)
		},
	})
	if err != nil {
		a.setStatus("Error")
		return err
	}
	AppendDesktopLog("INFO Book C attached (%s)", threatAttachLogSummary(threats))

	if err := writeSessionEnv(sess); err != nil {
		fmt.Fprintf(os.Stderr, "denyout desktop: session env: %v\n", err)
	}

	a.mu.Lock()
	a.session = sess
	a.proxyPort = sess.Port()
	a.state.Scope = ScopeSession
	a.state.ProtectionOn = true
	a.state.ComputerEnabled = false
	a.status = "Session (proxy)"
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	return nil
}

func (a *App) onSessionDeny(host string, reasons []string, redactedURL string) {
	a.mu.Lock()
	a.lastDeny = host
	a.state.LastDenyHost = host
	a.state.LastDenySummary = notify.HumanReasons(reasons)
	a.state.LastDenyURL = strings.TrimSpace(redactedURL)
	ask := a.state.AskMode
	sess := a.session
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
	if isIPLiteral(host) {
		if a.asks == nil {
			a.asks = newAskFlight()
		}
		a.asks.notifyIPBlocked(host)
		return
	}
	if ask && hostNotAllowed {
		go func() {
			switch a.coalescedAsk(host, "host_not_allowed") {
			case "once":
				if sess != nil {
					sess.AllowHost(host, "user_once")
				}
			case "always":
				_ = a.persistAlwaysHost(host)
			}
		}()
		return
	}
	a.mu.Lock()
	safe := normalizePolicyProfile(a.state.PolicyProfile) == PolicyProfileBrowse && !ask
	a.mu.Unlock()
	if safe && isClearPostBlock(reasons) {
		go a.handlePostBlockDeny(host, reasons, redactedURL)
		return
	}
	notify.Deny(host, reasons, redactedURL)
}

func (a *App) stopSession() {
	a.stopSessionKeep(false)
}

func (a *App) stopSessionKeep(keepRestore bool) {
	a.mu.Lock()
	sess := a.session
	a.session = nil
	if !keepRestore && a.state.Scope == ScopeSession {
		a.state.ProtectionOn = false
		a.state.ComputerEnabled = false
	}
	if a.proxyd == nil {
		a.status = "Off"
		a.proxyPort = 0
	}
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	clearSessionEnv()
	if sess != nil {
		_ = sess.Stop()
	}
}

func writeSessionEnv(sess *run.Session) error {
	st := sess.Status()
	proxyURL := st.ProxyURL
	caFile := sess.CACertFile()
	if proxyURL == "" {
		return fmt.Errorf("empty proxy url")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	cfgDir := filepath.Join(home, ".config", "denyout")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# DenyOut session proxy - apps that honor HTTP(S)_PROXY\n")
	b.WriteString("HTTP_PROXY=" + proxyURL + "\n")
	b.WriteString("HTTPS_PROXY=" + proxyURL + "\n")
	b.WriteString("http_proxy=" + proxyURL + "\n")
	b.WriteString("https_proxy=" + proxyURL + "\n")
	b.WriteString("NO_PROXY=localhost,127.0.0.1,::1\n")
	b.WriteString("no_proxy=localhost,127.0.0.1,::1\n")
	if caFile != "" {
		b.WriteString("SSL_CERT_FILE=" + caFile + "\n")
		b.WriteString("REQUESTS_CA_BUNDLE=" + caFile + "\n")
		b.WriteString("NODE_EXTRA_CA_CERTS=" + caFile + "\n")
		b.WriteString("DENYOUT_CA_CERT=" + caFile + "\n")
	}
	b.WriteString("DENYOUT_PROXY=" + proxyURL + "\n")
	content := b.String()
	if err := os.WriteFile(filepath.Join(cfgDir, "session-env"), []byte(content), 0o644); err != nil {
		return err
	}

	switch runtime.GOOS {
	case "linux":
		envDir := filepath.Join(home, ".config", "environment.d")
		_ = os.MkdirAll(envDir, 0o755)
		_ = os.WriteFile(filepath.Join(envDir, "90denyout.conf"), []byte(content), 0o644)
	case "darwin":
		// LaunchAgent env is updated in autostart plist when protection starts.
		_ = updateMacAutostartEnv(proxyURL, caFile)
	case "windows":
		_ = writeWindowsUserProxy(proxyURL, caFile)
	}
	return nil
}

func clearSessionEnv() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	_ = os.Remove(filepath.Join(home, ".config", "denyout", "session-env"))
	if runtime.GOOS == "linux" {
		_ = os.Remove(filepath.Join(home, ".config", "environment.d", "90denyout.conf"))
	}
	if runtime.GOOS == "darwin" {
		_ = updateMacAutostartEnv("", "")
	}
	if runtime.GOOS == "windows" {
		_ = clearWindowsUserProxy()
	}
}
