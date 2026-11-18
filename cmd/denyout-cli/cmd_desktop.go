package main

import (
	"context"

	"github.com/nareyko/denyout/internal/desktop"
)

const desktopUsage = `Usage: denyout-cli desktop [--install] [--setup] [--no-tray] [--web-ui] [--no-open] [--config path]

  Default: tray + restore protection from state (no browser UI).
  Scopes: whole computer (hostguard, admin) or session (HTTP proxy env, no admin).

  --install  silent setup: autostart, try computer once, fallback session, detach tray
  --web-ui   optional localhost settings page (tests / advanced only)
  --no-open  with --web-ui, do not open a browser
  --setup    mark first-run done (silent defaults)

  Install: install.sh → denyout-cli desktop --install on Desktop machines.`

type desktopOpts struct {
	cfgPath    string
	forceSetup bool
	noTray     bool
	noOpen     bool
	webUI      bool
	install    bool
	listen     string
}

// parseDesktopArgs parses and validates `desktop` flags (pure).
func parseDesktopArgs(args []string) (desktopOpts, *cliExit) {
	o := desktopOpts{listen: "127.0.0.1:0"}
	fs := flagSet{
		cmd:  "desktop",
		help: desktopUsage,
		values: []flagSpec{
			{names: []string{"--config", "-c"}, set: setStr(&o.cfgPath), missing: "--config requires a path"},
			{names: []string{"--listen"}, eq: true, missing: "--listen requires a value", set: func(v string) string {
				o.listen = v
				o.webUI = true
				return ""
			}},
		},
		bools: map[string]func(){
			"--install": func() { o.install = true },
			"--setup":   func() { o.forceSetup = true },
			"--no-tray": func() { o.noTray = true },
			"--no-open": func() { o.noOpen = true },
			"--web-ui":  func() { o.webUI = true },
		},
		unknown: "unknown flag %q",
	}
	if ex := fs.parse(args); ex != nil {
		return o, ex
	}
	if !o.install && o.webUI && !localListen(o.listen) {
		return o, failExit("denyout-cli desktop: --listen must be 127.0.0.1 or localhost")
	}
	return o, nil
}

// desktop entry points; swappable in tests.
var (
	desktopInstall = desktop.Install
	desktopRun     = desktop.Run
)

func runDesktop(o desktopOpts) *cliExit {
	if o.install {
		if err := desktopInstall(desktop.Options{ConfigPath: o.cfgPath, Version: version}); err != nil {
			return failExit("denyout-cli desktop --install: %v", err)
		}
		return &cliExit{}
	}
	ctx, stop := notifyContext()
	defer stop()
	return runDesktopCtx(ctx, o)
}

func runDesktopCtx(ctx context.Context, o desktopOpts) *cliExit {
	if err := desktopRun(ctx, desktop.Options{
		ConfigPath: o.cfgPath,
		Version:    version,
		ForceSetup: o.forceSetup,
		NoTray:     o.noTray,
		NoOpen:     o.noOpen,
		WebUI:      o.webUI,
		Listen:     o.listen,
	}); err != nil {
		return failExit("denyout-cli desktop: %v", err)
	}
	return &cliExit{}
}

func cmdDesktop(args []string) int {
	o, ex := parseDesktopArgs(args)
	if ex != nil {
		return ex.emit()
	}
	return runDesktop(o).emit()
}
