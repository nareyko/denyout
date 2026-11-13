package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/nareyko/denyout/internal/check"
	"github.com/nareyko/denyout/internal/desktop"
	"github.com/nareyko/denyout/internal/gui"
	"github.com/nareyko/denyout/internal/lab"
	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/proxy"
	"github.com/nareyko/denyout/internal/run"
	"github.com/nareyko/denyout/internal/serve"
)

// version is overridden at link time via -ldflags "-X main.version=…".
var version = "0.0.0-dev"

func main() {
	os.Exit(runMain(os.Args[1:]))
}

func runMain(args []string) int {
	if len(args) == 0 {
		printHelp(os.Stderr)
		return 2
	}

	switch args[0] {
	case "version", "--version", "-V":
		fmt.Printf("denyout %s\n", version)
		return 0
	case "help", "--help", "-h":
		printHelp(os.Stdout)
		return 0
	case "check":
		return cmdCheck(args[1:])
	case "policy":
		return cmdPolicy(args[1:])
	case "init":
		return cmdInit(args[1:])
	case "run":
		return cmdRun(args[1:])
	case "test":
		return cmdTest(args[1:])
	case "gui":
		return cmdGUI(args[1:])
	case "desktop":
		return cmdDesktop(args[1:])
	case "serve":
		return cmdServe(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "denyout: unknown command %q\n\n", args[0])
		printHelp(os.Stderr)
		return 2
	}
}

func printHelp(w *os.File) {
	fmt.Fprint(w, `denyout — free egress seatbelt for AI agents

Usage:
  denyout <command> [arguments]

Commands:
  version              Print version
  help                 Show this help
  init                 Write starter denyout.yaml
  check <url>          Evaluate a URL against policy (no network dial)
  policy validate <f>  Validate a denyout/v1 YAML config
  test [--db path]     Run lab SQLite fixtures (denyout test)
  run [flags] -- <cmd> Wrap command with local policy proxy
  desktop              Tray + setup wizard (recommended for non-technical use)
  gui                  Advanced localhost UI (technical)
  serve -c <file>      Long-running sidecar proxy (pair with NetworkPolicy)

Install and security boundaries: https://denyout.com · docs in this repo.
`)
}

func cmdCheck(args []string) int {
	cfgPath := ""
	url := ""
	jsonOut := false

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			jsonOut = true
		case a == "--config" || a == "-c":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout check: --config requires a path")
				return 2
			}
			cfgPath = args[i]
		case a == "--help" || a == "-h":
			fmt.Fprintln(os.Stdout, "Usage: denyout check [--config path] [--json] <url>")
			return 0
		case len(a) > 0 && a[0] == '-':
			fmt.Fprintf(os.Stderr, "denyout check: unknown flag %q\n", a)
			return 2
		default:
			if url != "" {
				fmt.Fprintln(os.Stderr, "denyout check: only one URL allowed")
				return 2
			}
			url = a
		}
	}

	if url == "" {
		fmt.Fprintln(os.Stderr, "denyout check: URL required")
		return 2
	}

	var cfg *policy.Config
	var err error
	if cfgPath != "" {
		cfg, err = policy.LoadFile(cfgPath)
	} else {
		cfg, err = policy.DefaultEnforceModels()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "denyout check: config: %v\n", err)
		return 2
	}

	res, err := check.URL(cfg, url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "denyout check: %v\n", err)
		return 2
	}

	if jsonOut {
		fmt.Println(res.JSON())
	} else {
		fmt.Println(res.Human())
	}

	if res.Verdict == check.VerdictDeny {
		return 1
	}
	return 0
}

func cmdPolicy(args []string) int {
	if len(args) == 0 || args[0] != "validate" {
		fmt.Fprintln(os.Stderr, "Usage: denyout policy validate <file>")
		return 2
	}
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "denyout policy validate: file required")
		return 2
	}
	if _, err := policy.LoadFile(args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "invalid: %v\n", err)
		return 2
	}
	fmt.Println("ok")
	return 0
}

func cmdInit(args []string) int {
	path := "denyout.yaml"
	for i := 0; i < len(args); i++ {
		if args[i] == "--help" || args[i] == "-h" {
			fmt.Println("Usage: denyout init [path]")
			return 0
		}
		if !strings.HasPrefix(args[i], "-") {
			path = args[i]
		}
	}
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(os.Stderr, "denyout init: %s already exists\n", path)
		return 2
	}
	content := `apiVersion: denyout/v1
kind: Config

metadata:
  name: local
  description: "Starter policy — preset models, enforce, TLS intercept"

mode: enforce
preset: models

tls:
  mode: intercept
  session_ca: true

listen:
  host: 127.0.0.1
  port: 0

allow_private: false
allow_ip_literals: false
deny_on_dns_failure: true

allowed_ports: [443, 80]

allow: []
deny: []

scanners:
  hard_secrets_in_audit_mode: true
  min_value_len: 6
  named_query:
    enabled: true
  high_entropy:
    enabled: false
  canaries:
    - "DENYOUT_CANARY_"
    - "ARVISER_CANARY_"

audit:
  jsonl_path: "~/.local/state/denyout/audit.jsonl"
  stdout: false
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "denyout init: %v\n", err)
		return 2
	}
	fmt.Printf("wrote %s\n", path)
	return 0
}

func cmdRun(args []string) int {
	cfgPath := ""
	tlsMode := string(proxy.TLSIntercept)
	sandbox := ""
	doNotify := true
	if os.Getenv("DENYOUT_NOTIFY") == "0" {
		doNotify = false
	}
	var cmdArgs []string

	dash := -1
	for i, a := range args {
		if a == "--" {
			dash = i
			break
		}
	}
	flagArgs := args
	if dash >= 0 {
		flagArgs = args[:dash]
		cmdArgs = args[dash+1:]
	}

	for i := 0; i < len(flagArgs); i++ {
		a := flagArgs[i]
		switch {
		case a == "--help" || a == "-h":
			fmt.Println("Usage: denyout run [--config path] [--tls-mode intercept|passthrough] [--sandbox=name] [--notify|--no-notify] -- <command>...")
			return 0
		case a == "--config" || a == "-c":
			i++
			if i >= len(flagArgs) {
				fmt.Fprintln(os.Stderr, "denyout run: --config requires a path")
				return 2
			}
			cfgPath = flagArgs[i]
		case strings.HasPrefix(a, "--tls-mode="):
			tlsMode = strings.TrimPrefix(a, "--tls-mode=")
		case a == "--tls-mode":
			i++
			if i >= len(flagArgs) {
				fmt.Fprintln(os.Stderr, "denyout run: --tls-mode requires a value")
				return 2
			}
			tlsMode = flagArgs[i]
		case strings.HasPrefix(a, "--sandbox="):
			sandbox = strings.TrimPrefix(a, "--sandbox=")
		case a == "--sandbox":
			i++
			if i >= len(flagArgs) {
				fmt.Fprintln(os.Stderr, "denyout run: --sandbox requires a value")
				return 2
			}
			sandbox = flagArgs[i]
		case a == "--notify":
			doNotify = true
		case a == "--no-notify":
			doNotify = false
		default:
			fmt.Fprintf(os.Stderr, "denyout run: unknown flag %q (command must follow --)\n", a)
			return 2
		}
	}

	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "denyout run: missing -- <command>")
		return 2
	}

	mode := proxy.TLSMode(tlsMode)
	if mode != proxy.TLSIntercept && mode != proxy.TLSPassthrough {
		fmt.Fprintf(os.Stderr, "denyout run: invalid tls-mode %q\n", tlsMode)
		return 2
	}

	code, err := run.Exec(run.Options{
		ConfigPath: cfgPath,
		TLSMode:    mode,
		Version:    version,
		Command:    cmdArgs,
		Sandbox:    sandbox,
		Notify:     doNotify || os.Getenv("DENYOUT_DESKTOP_NOTIFY") == "1",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "denyout run: %v\n", err)
		if code == 0 {
			return 2
		}
	}
	return code
}

func cmdDesktop(args []string) int {
	cfgPath := ""
	forceSetup := false
	noTray := false
	noOpen := false
	listen := "127.0.0.1:0"

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--help" || a == "-h":
			fmt.Println(`Usage: denyout desktop [--setup] [--no-tray] [--no-open] [--config path]

  Recommended entry for non-technical use: setup wizard + system tray/menu bar
  + desktop notifications when something is blocked.

  Install paths:
    CLI:  install.sh finishes with optional "denyout desktop"
    UI:   Windows — double-click Start-DenyOut.cmd from the zip`)
			return 0
		case a == "--setup":
			forceSetup = true
		case a == "--no-tray":
			noTray = true
		case a == "--no-open":
			noOpen = true
		case a == "--config" || a == "-c":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout desktop: --config requires a path")
				return 2
			}
			cfgPath = args[i]
		case strings.HasPrefix(a, "--listen="):
			listen = strings.TrimPrefix(a, "--listen=")
		case a == "--listen":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout desktop: --listen requires a value")
				return 2
			}
			listen = args[i]
		default:
			fmt.Fprintf(os.Stderr, "denyout desktop: unknown flag %q\n", a)
			return 2
		}
	}

	if !strings.HasPrefix(listen, "127.0.0.1:") && !strings.HasPrefix(listen, "localhost:") {
		fmt.Fprintln(os.Stderr, "denyout desktop: --listen must be 127.0.0.1 or localhost")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := desktop.Run(ctx, desktop.Options{
		ConfigPath: cfgPath,
		Version:    version,
		ForceSetup: forceSetup,
		NoTray:     noTray,
		NoOpen:     noOpen,
		Listen:     listen,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "denyout desktop: %v\n", err)
		return 2
	}
	return 0
}

func cmdServe(args []string) int {
	cfgPath := ""
	listen := ""
	metricsListen := ""
	healthListen := ""
	tlsMode := ""
	caDir := ""

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--help" || a == "-h":
			fmt.Println(`Usage: denyout serve --config path [--listen 127.0.0.1:8080] [--health-listen addr] [--metrics-listen addr] [--tls-mode intercept|passthrough] [--ca-dir path]

  Long-running policy proxy for sidecar / compose / systemd.
  Same engine as denyout run. Hardened deployments MUST pair with NetworkPolicy
  (or host firewall) so the agent cannot bypass the proxy — docs/08-server.md.

  DENYOUT_KILL=1 refuses to start (fail closed).`)
			return 0
		case a == "--config" || a == "-c":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout serve: --config requires a path")
				return 2
			}
			cfgPath = args[i]
		case strings.HasPrefix(a, "--listen="):
			listen = strings.TrimPrefix(a, "--listen=")
		case a == "--listen":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout serve: --listen requires a value")
				return 2
			}
			listen = args[i]
		case strings.HasPrefix(a, "--metrics-listen="):
			metricsListen = strings.TrimPrefix(a, "--metrics-listen=")
		case a == "--metrics-listen":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout serve: --metrics-listen requires a value")
				return 2
			}
			metricsListen = args[i]
		case strings.HasPrefix(a, "--health-listen="):
			healthListen = strings.TrimPrefix(a, "--health-listen=")
		case a == "--health-listen":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout serve: --health-listen requires a value")
				return 2
			}
			healthListen = args[i]
		case strings.HasPrefix(a, "--tls-mode="):
			tlsMode = strings.TrimPrefix(a, "--tls-mode=")
		case a == "--tls-mode":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout serve: --tls-mode requires a value")
				return 2
			}
			tlsMode = args[i]
		case strings.HasPrefix(a, "--ca-dir="):
			caDir = strings.TrimPrefix(a, "--ca-dir=")
		case a == "--ca-dir":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout serve: --ca-dir requires a path")
				return 2
			}
			caDir = args[i]
		default:
			fmt.Fprintf(os.Stderr, "denyout serve: unknown flag %q\n", a)
			return 2
		}
	}

	if cfgPath == "" {
		fmt.Fprintln(os.Stderr, "denyout serve: --config is required")
		return 2
	}

	var mode proxy.TLSMode
	if tlsMode != "" {
		mode = proxy.TLSMode(tlsMode)
		if mode != proxy.TLSIntercept && mode != proxy.TLSPassthrough {
			fmt.Fprintf(os.Stderr, "denyout serve: invalid tls-mode %q\n", tlsMode)
			return 2
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := serve.Run(ctx, serve.Options{
		ConfigPath:    cfgPath,
		Listen:        listen,
		MetricsListen: metricsListen,
		HealthListen:  healthListen,
		TLSMode:       mode,
		CADir:         caDir,
		Version:       version,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "denyout serve: %v\n", err)
		return 2
	}
	return 0
}

func cmdGUI(args []string) int {
	cfgPath := ""
	tlsMode := string(proxy.TLSIntercept)
	listen := "127.0.0.1:0"
	openBrowser := true

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--help" || a == "-h":
			fmt.Println("Usage: denyout gui [--config path] [--tls-mode intercept|passthrough] [--listen 127.0.0.1:0] [--no-open]")
			fmt.Println("  Localhost web UI: start/stop wrap, mode/preset, check URL, recent redacted denials.")
			fmt.Println("  Same policy engine as CLI; does not bypass denyout run.")
			return 0
		case a == "--no-open":
			openBrowser = false
		case a == "--config" || a == "-c":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout gui: --config requires a path")
				return 2
			}
			cfgPath = args[i]
		case strings.HasPrefix(a, "--tls-mode="):
			tlsMode = strings.TrimPrefix(a, "--tls-mode=")
		case a == "--tls-mode":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout gui: --tls-mode requires a value")
				return 2
			}
			tlsMode = args[i]
		case strings.HasPrefix(a, "--listen="):
			listen = strings.TrimPrefix(a, "--listen=")
		case a == "--listen":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout gui: --listen requires a value")
				return 2
			}
			listen = args[i]
		default:
			fmt.Fprintf(os.Stderr, "denyout gui: unknown flag %q\n", a)
			return 2
		}
	}

	mode := proxy.TLSMode(tlsMode)
	if mode != proxy.TLSIntercept && mode != proxy.TLSPassthrough {
		fmt.Fprintf(os.Stderr, "denyout gui: invalid tls-mode %q\n", tlsMode)
		return 2
	}
	if !strings.HasPrefix(listen, "127.0.0.1:") && !strings.HasPrefix(listen, "localhost:") {
		fmt.Fprintln(os.Stderr, "denyout gui: --listen must be 127.0.0.1 or localhost (desktop UI is local-only)")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := gui.Run(ctx, gui.Options{
		ConfigPath:  cfgPath,
		TLSMode:     mode,
		Version:     version,
		Listen:      listen,
		OpenBrowser: openBrowser,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "denyout gui: %v\n", err)
		return 2
	}
	return 0
}

func cmdTest(args []string) int {
	dbPath := "examples/fixtures/denyout-lab.sqlite"
	suite := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--help" || a == "-h":
			fmt.Println("Usage: denyout test [--db path] [--suite name]")
			fmt.Println("  Seeds the lab DB if needed, runs active fixtures (no network dial).")
			return 0
		case a == "--db":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout test: --db requires a path")
				return 2
			}
			dbPath = args[i]
		case strings.HasPrefix(a, "--db="):
			dbPath = strings.TrimPrefix(a, "--db=")
		case a == "--suite":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout test: --suite requires a name")
				return 2
			}
			suite = args[i]
		case strings.HasPrefix(a, "--suite="):
			suite = strings.TrimPrefix(a, "--suite=")
		default:
			fmt.Fprintf(os.Stderr, "denyout test: unknown flag %q\n", a)
			return 2
		}
	}

	db, err := lab.OpenSeeded(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "denyout test: %v\n", err)
		return 2
	}
	defer db.Close()

	if suite == "r20_url" {
		n, err := lab.CountActive(db, "r20_url")
		if err != nil {
			fmt.Fprintf(os.Stderr, "denyout test: %v\n", err)
			return 2
		}
		if n < 20 {
			fmt.Fprintf(os.Stderr, "denyout test: r20_url active=%d want >=20 (M1)\n", n)
			return 2
		}
	}

	rep, err := lab.RunDB(db, lab.RunOptions{Suite: suite, Label: "cli"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "denyout test: %v\n", err)
		return 2
	}

	for _, r := range rep.Results {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		}
		fmt.Printf("%s %s suite=%s verdict=%s reasons=%v %s\n", status, r.CaseID, r.Suite, r.Verdict, r.Reasons, r.Detail)
	}
	fmt.Printf("summary run_id=%s passed=%d failed=%d total=%d db=%s\n", rep.RunID, rep.Passed, rep.Failed, rep.Total, dbPath)
	if rep.Failed > 0 {
		return 1
	}
	return 0
}
