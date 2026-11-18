package main

import (
	"fmt"
	"os"

	"github.com/nareyko/denyout/internal/tun"
)

func tunRollbackPlan() string {
	return tun.FormatRollbackPlan()
}

// version is overridden at link time via -ldflags "-X main.version=…".
var version = "0.0.0-dev"

func main() {
	os.Exit(runMain(os.Args[1:]))
}

// commands is the top-level dispatch table (command name -> handler).
var commands = map[string]func(args []string) int{
	"version":   cmdVersion,
	"--version": cmdVersion,
	"-V":        cmdVersion,
	"help":      cmdHelp,
	"--help":    cmdHelp,
	"-h":        cmdHelp,
	"check":     cmdCheck,
	"policy":    cmdPolicy,
	"config":    cmdConfig,
	"init":      cmdInit,
	"run":       cmdRun,
	"profile":   cmdProfile,
	"test":      cmdTest,
	"gui":       cmdGUI,
	"desktop":   cmdDesktop,
	"hostctl":   cmdHostctl,
	"uninstall": cmdUninstall,
	"serve":     cmdServe,
	"audit":     cmdAudit,
	"doctor":    func(args []string) int { return cmdDoctor(args, os.Stdout, os.Stderr) },
}

func cmdVersion([]string) int {
	fmt.Printf("denyout-cli %s\n", version)
	return 0
}

func cmdHelp([]string) int {
	printHelp(os.Stdout)
	return 0
}

func runMain(args []string) int {
	if len(args) == 0 {
		printHelp(os.Stderr)
		return 2
	}
	if h, ok := commands[args[0]]; ok {
		return h(args[1:])
	}
	fmt.Fprintf(os.Stderr, "denyout-cli: unknown command %q\n\n", args[0])
	printHelp(os.Stderr)
	return 2
}

func printHelp(w *os.File) {
	fmt.Fprint(w, `denyout-cli — free egress seatbelt for AI agents

Usage:
  denyout-cli <command> [arguments]

Commands:
  version              Print version
  help                 Show this help
  init                 Write starter denyout.yaml
  check <url>          Evaluate a URL against policy (no network dial)
  policy check <f>     Validate a denyout/v1 YAML config (line-accurate errors; alias: validate)
  config show          Effective settings with the source of each value (secrets redacted)
  test [--db path]     Run lab SQLite fixtures (denyout-cli test)
  run [flags] -- <cmd> Wrap command with local policy proxy
  profile              Manage named agent wrap profiles
  desktop              Tray + Protect this computer (recommended)
  hostctl              Privileged helper for transparent redirect + CA (elevated)
  uninstall            Remove install: processes, hostguard, CA, config, binaries
  gui                  Advanced localhost UI (technical)
  serve -c <file>      Long-running sidecar proxy (pair with NetworkPolicy)
  audit tail           Show recent audit.jsonl events (desktop path by default)
  doctor               Redacted status report to paste into a bug report

Install and security boundaries: https://denyout.com · docs in this repo.
`)
}
