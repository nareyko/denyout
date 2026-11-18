package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/nareyko/denyout/internal/notify"
	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/proxy"
	"github.com/nareyko/denyout/internal/run"
	"github.com/nareyko/denyout/internal/settings"
	"github.com/nareyko/denyout/internal/threatlists"
)

type proxydOpts struct {
	port       int
	caDir      string
	ask        bool
	allowBase  string
	controlURL string
}

// parseProxydArgs parses `hostctl proxyd` flags (pure).
func parseProxydArgs(args []string) (proxydOpts, *cliExit) {
	var o proxydOpts
	fs := flagSet{
		cmd: "hostctl proxyd",
		values: []flagSpec{
			{names: []string{"--port"}, eq: true, set: setInt(&o.port)},
			{names: []string{"--ca-dir"}, eq: true, set: setStr(&o.caDir)},
			{names: []string{"--allow-base"}, eq: true, set: setStr(&o.allowBase)},
			{names: []string{"--control-url"}, eq: true, set: setStr(&o.controlURL)},
		},
		bools:   map[string]func(){"--ask": func() { o.ask = true }},
		unknown: "unknown flag %q",
	}
	if ex := fs.parse(args); ex != nil {
		return o, ex
	}
	if o.port <= 0 || o.caDir == "" {
		return o, failExit("denyout-cli hostctl proxyd: --port and --ca-dir required")
	}
	return o, nil
}

// proxydPolicy builds the whole-device policy for the proxyd process from the
// options and environment (pure given getenv). It also returns the policy
// profile name ("agent" by default, or "browse").
func proxydPolicy(o proxydOpts, getenv func(string) string) (*policy.Config, string, error) {
	var rules []policy.Rule
	for _, h := range settings.EnvList(getenv("DENYOUT_ALWAYS_ALLOW")) {
		rules = append(rules, policy.Rule{Host: h, Reason: "user_always"})
	}
	profile := strings.ToLower(strings.TrimSpace(getenv("DENYOUT_POLICY_PROFILE")))
	if profile == "" {
		profile = "agent"
	}
	var cfg *policy.Config
	var err error
	switch {
	case profile == "browse":
		cfg, err = policy.DefaultWholeDeviceBrowse()
		if err == nil && len(rules) > 0 {
			cfg.Allow = append(cfg.Allow, rules...)
		}
	case o.ask || len(rules) > 0:
		cfg, err = policy.DefaultWholeDeviceAsk(rules)
	default:
		cfg, err = policy.DefaultWholeDevice()
	}
	if err != nil {
		return nil, "", err
	}
	if settings.EnvBool(getenv("DENYOUT_ALLOW_PRIVATE")) {
		cfg.AllowPrivate = true
	}
	return cfg, profile, nil
}

// denyAction is what proxyd does about one denied connection.
type denyAction int

const (
	denyNotify      denyAction = iota // local toast
	denyReport                        // post to the tray control API (it toasts)
	denyAskControl                    // post silently, then ask via the tray dialog
	denyAskNotifier                   // desktop Ask notification linking to the wizard
)

// decideDeny picks the action for a denied host (pure).
func decideDeny(o proxydOpts, host string, reasons []string) denyAction {
	// Raw IP literals: hard-deny toast only (no Ask). Control rate-limits.
	if net.ParseIP(host) == nil && o.ask && containsStr(reasons, "host_not_allowed") {
		if o.controlURL != "" {
			return denyAskControl
		}
		if o.allowBase != "" {
			return denyAskNotifier
		}
	}
	if o.controlURL != "" {
		return denyReport
	}
	return denyNotify
}

// askURL is the wizard link of an Ask notification.
func askURL(allowBase, host string) string {
	return strings.TrimRight(allowBase, "/") + "/allow.html?host=" + host
}

// denyDeps are the side effects of the deny handler.
type denyDeps struct {
	spawn       func(f func())
	postEvent   func(base, host string, reasons []string, redactedURL string, doNotify bool)
	ask         func(base, host string) string
	postAlways  func(base, host string)
	notifyDeny  func(host string, reasons []string, redactedURL string)
	notifyAsk   func(opts notify.AskOptions)
	allowHostFn func(host, reason string)
}

func realDenyDeps(allow func(host, reason string)) denyDeps {
	return denyDeps{
		spawn:       func(f func()) { go f() },
		postEvent:   postControlDenyEvent,
		ask:         askViaControl,
		postAlways:  postControlAlways,
		notifyDeny:  func(host string, reasons []string, u string) { notify.Deny(host, reasons, u) },
		notifyAsk:   notify.Ask,
		allowHostFn: allow,
	}
}

// newDenyHandler returns the proxy OnDeny callback.
func newDenyHandler(o proxydOpts, d denyDeps) func(host string, reasons []string, redactedURL string) {
	return func(host string, reasons []string, redactedURL string) {
		switch decideDeny(o, host, reasons) {
		case denyAskControl:
			// Update tray last-deny without toast; Ask dialog follows (coalesced).
			d.spawn(func() { d.postEvent(o.controlURL, host, reasons, redactedURL, false) })
			switch d.ask(o.controlURL, host) {
			case "once":
				d.allowHostFn(host, "user_once")
			case "always":
				d.allowHostFn(host, "user_always")
				d.postAlways(o.controlURL, host)
			}
		case denyAskNotifier:
			d.spawn(func() { d.notifyAsk(notify.AskOptions{Host: host, OpenURL: askURL(o.allowBase, host)}) })
		case denyReport:
			// Tray process owns toast + LastDenySummary (avoid duplicate notify).
			d.spawn(func() { d.postEvent(o.controlURL, host, reasons, redactedURL, true) })
		default:
			d.notifyDeny(host, reasons, redactedURL)
		}
	}
}

// proxySession is the part of *run.Session proxyd drives.
type proxySession interface {
	Port() int
	Stop() error
	AllowHost(host, reason string)
}

// proxydDeps are the side effects of proxyd, swappable in tests.
type proxydDeps struct {
	getenv       func(string) string
	openThreats  func(ctx context.Context) (policy.ThreatChecker, error)
	debugStats   func()
	startSession func(run.SessionOptions) (proxySession, error)
	// wait blocks until a stop signal, then runs onSignal while the signal
	// handler is still installed (a second signal must not kill the shutdown).
	wait     func(onSignal func())
	denyDeps func(allow func(host, reason string)) denyDeps
}

func realProxydDeps() proxydDeps {
	return proxydDeps{
		getenv: os.Getenv,
		openThreats: func(ctx context.Context) (policy.ThreatChecker, error) {
			att, err := threatlists.OpenAndRefresh(ctx, true)
			if err != nil {
				return nil, err
			}
			return att.Store, nil
		},
		debugStats: startDebugStats,
		startSession: func(so run.SessionOptions) (proxySession, error) {
			s, err := run.StartSession(so)
			if err != nil {
				return nil, err
			}
			return s, nil
		},
		wait: func(onSignal func()) {
			ctx, stop := notifyContext()
			defer stop()
			<-ctx.Done()
			onSignal()
		},
		denyDeps: realDenyDeps,
	}
}

// runProxyd starts the transparent proxy and blocks until signalled.
func runProxyd(o proxydOpts, d proxydDeps) int {
	cfg, profile, err := proxydPolicy(o, d.getenv)
	if err != nil {
		return failExit("denyout-cli hostctl proxyd: %v", err).emit()
	}
	var threats policy.ThreatChecker
	if t, err := d.openThreats(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "denyout-cli hostctl proxyd: threatlists: %v (continuing)\n", err)
	} else {
		threats = t
	}
	d.debugStats()
	var sess proxySession
	allow := func(host, reason string) {
		if sess != nil {
			sess.AllowHost(host, reason)
		}
	}
	s, err := d.startSession(run.SessionOptions{
		Config:             cfg,
		TLSMode:            proxy.TLSIntercept,
		Version:            version,
		CADir:              o.caDir,
		PersistCA:          true,
		Transparent:        true,
		ListenPort:         o.port,
		PolicyProfile:      profile,
		Process:            "proxyd",
		Threats:            threats,
		InsecureSkipVerify: settings.EnvBool(d.getenv("DENYOUT_TLS_INSECURE_UPSTREAM")),
		OnDeny:             newDenyHandler(o, d.denyDeps(allow)),
	})
	if err != nil {
		return failExit("denyout-cli hostctl proxyd: %v", err).emit()
	}
	sess = s
	fmt.Fprintf(os.Stderr, "denyout-cli hostctl proxyd: listening :%d transparent\n", s.Port())
	d.wait(func() { _ = s.Stop() })
	return 0
}

func cmdHostctlProxyd(args []string) int {
	o, ex := parseProxydArgs(args)
	if ex != nil {
		return ex.emit()
	}
	return runProxyd(o, realProxydDeps())
}
