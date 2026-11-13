package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/nareyko/denyout/internal/check"
	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/proxy"
	"github.com/nareyko/denyout/internal/run"
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
  run [flags] -- <cmd> Wrap command with local policy proxy

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
			fmt.Println("Usage: denyout run [--config path] [--tls-mode intercept|passthrough] [--sandbox=name] -- <command>...")
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
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "denyout run: %v\n", err)
		if code == 0 {
			return 2
		}
	}
	return code
}
