package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// CLI verbs that belong to denyout-cli — never start the Wails tray/UI for these.
var denyoutCLICommands = map[string]struct{}{
	"check":     {},
	"policy":    {},
	"init":      {},
	"run":       {},
	"profile":   {},
	"test":      {},
	"gui":       {},
	"desktop":   {},
	"hostctl":   {},
	"uninstall": {},
	"serve":     {},
	"audit":     {},
}

// handleGUIQuickArgs handles version/help and refuses CLI verbs / unknown bare
// words before ReexecDetachedIfTTY or Wails bootstrap. Returns handled=true when
// the process should exit with code (no GUI).
//
// Root cause of "denyout version" spawning a second tray: only --version was
// wired; positional "version" fell through to detach + full app start.
func handleGUIQuickArgs(args []string, ver string, stdout, stderr io.Writer) (code int, handled bool) {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	if len(args) == 0 {
		return 0, false
	}

	first := strings.TrimSpace(args[0])
	if first == "" {
		return 0, false
	}

	switch first {
	case "version", "--version", "-V":
		fmt.Fprintf(stdout, "denyout %s\n", ver)
		return 0, true
	case "help", "--help", "-h":
		printGUIHelp(stdout, ver)
		return 0, true
	}

	if _, ok := denyoutCLICommands[first]; ok {
		fmt.Fprintf(stderr, "denyout: %q is a denyout-cli command — not the desktop app.\n\n  denyout-cli %s\n\n", first, strings.Join(args, " "))
		fmt.Fprintf(stderr, "Desktop app: denyout | denyout --open | denyout --version\n")
		return 2, true
	}

	// Unknown bare word (docs sometimes say `denyout version`; typos must not
	// spawn another tray via ReexecDetachedIfTTY).
	if !strings.HasPrefix(first, "-") {
		fmt.Fprintf(stderr, "denyout: unknown argument %q\n\n", first)
		printGUIHelp(stderr, ver)
		return 2, true
	}

	return 0, false
}

func printGUIHelp(w io.Writer, ver string) {
	fmt.Fprintf(w, `denyout %s — DenyOut desktop (tray + window)

Usage:
  denyout                 Start tray/UI (detaches from terminal)
  denyout --open          Show window on start
  denyout --foreground    Keep attached to this terminal
  denyout --no-tray       Window only (debug)
  denyout version | --version | -V
  denyout help | --help | -h

CLI / Protect helpers (separate binary):
  denyout-cli version
  denyout-cli check <url>
  denyout-cli run -- <cmd>
  denyout-cli hostctl …
  denyout-cli uninstall

`, ver)
}
