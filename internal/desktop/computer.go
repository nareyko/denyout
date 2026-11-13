package desktop

import (
	"fmt"

	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/notify"
	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/proxy"
	"github.com/nareyko/denyout/internal/run"
)

func (a *App) startComputer() error {
	a.mu.Lock()
	if a.session != nil {
		a.mu.Unlock()
		return fmt.Errorf("Protect this computer is already on")
	}
	ask := a.state.AskMode
	allows := append([]string{}, a.state.AlwaysAllowHosts...)
	a.status = "Starting…"
	a.mu.Unlock()

	var cfg *policy.Config
	var err error
	if ask {
		rules := make([]policy.Rule, 0, len(allows))
		for _, h := range allows {
			rules = append(rules, policy.Rule{Host: h, Reason: "user_always"})
		}
		cfg, err = policy.DefaultWholeDeviceAsk(rules)
	} else {
		cfg, err = policy.DefaultWholeDevice()
	}
	if err != nil {
		a.setStatus("Error")
		return err
	}
	if a.opts.ConfigPath != "" {
		cfg, err = policy.LoadFile(a.opts.ConfigPath)
		if err != nil {
			a.setStatus("Error")
			return err
		}
	}

	sess, err := run.StartSession(run.SessionOptions{
		Config:      cfg,
		TLSMode:     proxy.TLSIntercept,
		Version:     a.opts.Version,
		CADir:       CADir(),
		PersistCA:   true,
		Transparent: true,
		ListenPort:  0,
		OnDeny: func(host string, reasons []string) {
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
				notify.AskNotify(host)
			} else {
				notify.Deny(host, reasons)
			}
		},
	})
	if err != nil {
		a.setStatus("Error")
		return err
	}

	uid, _ := hostguard.CurrentUID()
	spec := hostguard.Spec{
		ProxyPort: sess.Port(),
		UID:       uid,
		CACert:    sess.CACertFile(),
	}
	if err := hostguard.ElevateApply(spec.ProxyPort, spec.CACert, spec.UID); err != nil {
		_ = sess.Stop()
		a.setStatus("Needs admin")
		return err
	}

	a.mu.Lock()
	a.session = sess
	a.state.ComputerEnabled = true
	a.status = "Protecting computer"
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)
	return nil
}

func (a *App) stopComputer() {
	a.mu.Lock()
	sess := a.session
	a.session = nil
	port := 0
	if sess != nil {
		port = sess.Port()
	}
	a.state.ComputerEnabled = false
	a.status = "Off"
	st := a.state
	a.mu.Unlock()
	_ = SaveState(st)

	if sess != nil {
		uid, _ := hostguard.CurrentUID()
		_ = hostguard.ElevateRemove(port, uid)
		_ = sess.Stop()
	}
}

func (a *App) setStatus(s string) {
	a.mu.Lock()
	a.status = s
	a.mu.Unlock()
}

func (a *App) allowHostAlways(host string) error {
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
	wasOn := a.session != nil
	a.mu.Unlock()
	if err := SaveState(st); err != nil {
		return err
	}
	if wasOn {
		a.stopComputer()
		return a.startComputer()
	}
	return nil
}
