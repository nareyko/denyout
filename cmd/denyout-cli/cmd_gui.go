package main

import (
	"github.com/nareyko/denyout/internal/gui"
	"github.com/nareyko/denyout/internal/proxy"
)

const guiUsage = `Usage: denyout-cli gui [--config path] [--tls-mode intercept|passthrough] [--listen 127.0.0.1:0] [--no-open]
  Localhost web UI: start/stop wrap, mode/preset, check URL, recent redacted denials.
  Same policy engine as CLI; does not bypass denyout-cli run.`

// parseGUIArgs parses and validates `gui` flags into gui.Options (pure).
func parseGUIArgs(args []string) (gui.Options, *cliExit) {
	o := gui.Options{Listen: "127.0.0.1:0", OpenBrowser: true}
	tlsMode := string(proxy.TLSIntercept)
	fs := flagSet{
		cmd:  "gui",
		help: guiUsage,
		values: []flagSpec{
			{names: []string{"--config", "-c"}, set: setStr(&o.ConfigPath), missing: "--config requires a path"},
			{names: []string{"--tls-mode"}, eq: true, set: setStr(&tlsMode), missing: "--tls-mode requires a value"},
			{names: []string{"--listen"}, eq: true, set: setStr(&o.Listen), missing: "--listen requires a value"},
		},
		bools:   map[string]func(){"--no-open": func() { o.OpenBrowser = false }},
		unknown: "unknown flag %q",
	}
	if ex := fs.parse(args); ex != nil {
		return o, ex
	}
	o.TLSMode = proxy.TLSMode(tlsMode)
	if o.TLSMode != proxy.TLSIntercept && o.TLSMode != proxy.TLSPassthrough {
		return o, failExit("denyout-cli gui: invalid tls-mode %q", tlsMode)
	}
	if !localListen(o.Listen) {
		return o, failExit("denyout-cli gui: --listen must be 127.0.0.1 or localhost (desktop UI is local-only)")
	}
	o.Version = version
	return o, nil
}

// guiRun runs the localhost UI; swappable in tests.
var guiRun = gui.Run

func cmdGUI(args []string) int {
	o, ex := parseGUIArgs(args)
	if ex != nil {
		return ex.emit()
	}
	ctx, stop := notifyContext()
	defer stop()
	if err := guiRun(ctx, o); err != nil {
		return failExit("denyout-cli gui: %v", err).emit()
	}
	return 0
}
