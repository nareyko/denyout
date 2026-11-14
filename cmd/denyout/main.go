package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/check"
	"github.com/nareyko/denyout/internal/desktop"
	"github.com/nareyko/denyout/internal/gui"
	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/lab"
	"github.com/nareyko/denyout/internal/notify"
	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/proxy"
	"github.com/nareyko/denyout/internal/run"
	"github.com/nareyko/denyout/internal/serve"
	"github.com/nareyko/denyout/internal/threatlists"
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
	case "profile":
		return cmdProfile(args[1:])
	case "test":
		return cmdTest(args[1:])
	case "gui":
		return cmdGUI(args[1:])
	case "desktop":
		return cmdDesktop(args[1:])
	case "hostctl":
		return cmdHostctl(args[1:])
	case "serve":
		return cmdServe(args[1:])
	case "audit":
		return cmdAudit(args[1:])
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
  profile              Manage named agent wrap profiles
  desktop              Tray + Protect this computer (recommended)
  hostctl              Privileged helper for transparent redirect + CA (elevated)
  gui                  Advanced localhost UI (technical)
  serve -c <file>      Long-running sidecar proxy (pair with NetworkPolicy)
  audit tail           Show recent audit.jsonl events (desktop path by default)

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
	profileID := ""
	requireSandbox := false
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
			fmt.Println("Usage: denyout run [--config path] [--profile id] [--tls-mode intercept|passthrough] [--sandbox=srt] [--notify|--no-notify] -- <command>...")
			return 0
		case a == "--config" || a == "-c":
			i++
			if i >= len(flagArgs) {
				fmt.Fprintln(os.Stderr, "denyout run: --config requires a path")
				return 2
			}
			cfgPath = flagArgs[i]
		case strings.HasPrefix(a, "--profile="):
			profileID = strings.TrimPrefix(a, "--profile=")
		case a == "--profile":
			i++
			if i >= len(flagArgs) {
				fmt.Fprintln(os.Stderr, "denyout run: --profile requires an id")
				return 2
			}
			profileID = flagArgs[i]
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

	if profileID != "" {
		p, err := desktop.LoadProfile(profileID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "denyout run: profile: %v\n", err)
			return 2
		}
		cfgFile, err := p.WriteTempConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "denyout run: profile config: %v\n", err)
			return 2
		}
		cfgPath = cfgFile
		if len(cmdArgs) == 0 {
			cmdArgs = append([]string{}, p.Command...)
		}
		if sandbox == "" {
			sandbox = p.Sandbox
		}
		requireSandbox = p.RequireIsolation
		if p.WorkDir != "" {
			if err := os.Chdir(p.WorkDir); err != nil {
				fmt.Fprintf(os.Stderr, "denyout run: workdir: %v\n", err)
				return 2
			}
		}
	}

	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "denyout run: missing -- <command> (or --profile with a command)")
		return 2
	}

	mode := proxy.TLSMode(tlsMode)
	if mode != proxy.TLSIntercept && mode != proxy.TLSPassthrough {
		fmt.Fprintf(os.Stderr, "denyout run: invalid tls-mode %q\n", tlsMode)
		return 2
	}

	code, err := run.Exec(run.Options{
		ConfigPath:     cfgPath,
		TLSMode:        mode,
		Version:        version,
		Command:        cmdArgs,
		Sandbox:        sandbox,
		RequireSandbox: requireSandbox,
		Notify:         doNotify || os.Getenv("DENYOUT_DESKTOP_NOTIFY") == "1",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "denyout run: %v\n", err)
		if code == 0 {
			return 2
		}
	}
	return code
}

func cmdProfile(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Println(`Usage: denyout profile <command>

  list                         List saved agent profiles
  create --name N -- <cmd>…    Create a profile (Agent+Cursor + learning)
  show <id>                    Print profile YAML path / summary
  delete <id>                  Delete a profile
  run <id>                     Run profile (same as denyout run --profile <id>)
  pin <id>                     Pin all pending Once hosts (learning)
  discard <id>                 Discard pending Once hosts

Profiles live in ~/.config/denyout/profiles/`)
		return 0
	}
	switch args[0] {
	case "list":
		list, err := desktop.ListProfiles()
		if err != nil {
			fmt.Fprintf(os.Stderr, "denyout profile list: %v\n", err)
			return 2
		}
		if len(list) == 0 {
			fmt.Println("(no profiles)")
			return 0
		}
		for _, p := range list {
			fmt.Printf("%s\t%s\t%s\tpending=%d\n", p.ID, p.Name, p.CommandLine(), len(p.PendingOnce))
		}
		return 0
	case "create":
		name := ""
		var cmdArgs []string
		rest := args[1:]
		dash := -1
		for i, a := range rest {
			if a == "--" {
				dash = i
				break
			}
		}
		flagArgs := rest
		if dash >= 0 {
			flagArgs = rest[:dash]
			cmdArgs = rest[dash+1:]
		}
		for i := 0; i < len(flagArgs); i++ {
			a := flagArgs[i]
			switch {
			case a == "--name":
				i++
				if i < len(flagArgs) {
					name = flagArgs[i]
				}
			case strings.HasPrefix(a, "--name="):
				name = strings.TrimPrefix(a, "--name=")
			default:
				fmt.Fprintf(os.Stderr, "denyout profile create: unknown flag %q\n", a)
				return 2
			}
		}
		if name == "" || len(cmdArgs) == 0 {
			fmt.Fprintln(os.Stderr, "denyout profile create: need --name and -- <command>")
			return 2
		}
		p := desktop.NewAgentProfile(name, cmdArgs)
		if err := desktop.SaveProfile(p); err != nil {
			fmt.Fprintf(os.Stderr, "denyout profile create: %v\n", err)
			return 2
		}
		fmt.Printf("created %s (%s)\n", p.ID, desktop.ProfilePathForCLI(p.ID))
		return 0
	case "show":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "denyout profile show: need id")
			return 2
		}
		p, err := desktop.LoadProfile(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "denyout profile show: %v\n", err)
			return 2
		}
		fmt.Printf("id=%s name=%q preset=%s ask=%v sandbox=%q pending=%v allow=%v\npath=%s\n",
			p.ID, p.Name, p.Preset, p.AskMode, p.Sandbox, p.PendingOnce, p.ExtraAllow, desktop.ProfilePathForCLI(p.ID))
		return 0
	case "delete":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "denyout profile delete: need id")
			return 2
		}
		if err := desktop.DeleteProfile(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "denyout profile delete: %v\n", err)
			return 2
		}
		fmt.Println("deleted", args[1])
		return 0
	case "run":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "denyout profile run: need id")
			return 2
		}
		return cmdRun([]string{"--profile", args[1]})
	case "pin":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "denyout profile pin: need id")
			return 2
		}
		p, err := desktop.LoadProfile(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "denyout profile pin: %v\n", err)
			return 2
		}
		n := len(p.PendingOnce)
		p.PinPending(nil)
		p.Learning.Enabled = false
		if err := desktop.SaveProfile(p); err != nil {
			fmt.Fprintf(os.Stderr, "denyout profile pin: %v\n", err)
			return 2
		}
		fmt.Printf("pinned %d host(s); learning off\n", n)
		return 0
	case "discard":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "denyout profile discard: need id")
			return 2
		}
		p, err := desktop.LoadProfile(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "denyout profile discard: %v\n", err)
			return 2
		}
		p.DiscardPending()
		if err := desktop.SaveProfile(p); err != nil {
			fmt.Fprintf(os.Stderr, "denyout profile discard: %v\n", err)
			return 2
		}
		fmt.Println("discarded pending")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "denyout profile: unknown %q\n", args[0])
		return 2
	}
}

func cmdHostctl(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Println(`Usage: denyout hostctl apply|remove|render|proxyd [flags]

  Privileged helper for Protect this computer (transparent redirect + CA trust).
  proxyd runs the transparent proxy (started after setcap so SO_MARK works).

Flags:
  --port N     local DenyOut proxy port
  --ca PATH    CA certificate PEM to trust
  --ca-dir D   persistent CA directory (proxyd)
  --uid N      desktop user uid (Unix)
  --ask        Ask mode policy (proxyd)
  --allow-base URL  wizard base for Ask allow page (proxyd)
  --no-elevate already running elevated (internal)`)
		return 0
	}
	action := args[0]
	if action == "proxyd" {
		return cmdHostctlProxyd(args[1:])
	}
	port := 0
	ca := ""
	uid := 0
	noElevate := false
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--no-elevate":
			noElevate = true
		case strings.HasPrefix(a, "--port="):
			fmt.Sscanf(strings.TrimPrefix(a, "--port="), "%d", &port)
		case a == "--port":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &port)
			}
		case strings.HasPrefix(a, "--ca="):
			ca = strings.TrimPrefix(a, "--ca=")
		case a == "--ca":
			i++
			if i < len(args) {
				ca = args[i]
			}
		case strings.HasPrefix(a, "--uid="):
			fmt.Sscanf(strings.TrimPrefix(a, "--uid="), "%d", &uid)
		case a == "--uid":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &uid)
			}
		default:
			fmt.Fprintf(os.Stderr, "denyout hostctl: unknown flag %q\n", a)
			return 2
		}
	}
	spec := hostguard.Spec{ProxyPort: port, UID: uid, CACert: ca}
	switch action {
	case "render":
		out, err := hostguard.Render(spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "denyout hostctl: %v\n", err)
			return 2
		}
		fmt.Print(out)
		return 0
	case "apply":
		if !noElevate {
			if err := hostguard.ElevateApply(port, ca, uid); err != nil {
				fmt.Fprintf(os.Stderr, "denyout hostctl: %v\n", err)
				return 2
			}
			return 0
		}
		if err := hostguard.Apply(spec); err != nil {
			fmt.Fprintf(os.Stderr, "denyout hostctl: %v\n", err)
			return 2
		}
		return 0
	case "remove":
		if !noElevate {
			if err := hostguard.ElevateRemove(port, uid); err != nil {
				fmt.Fprintf(os.Stderr, "denyout hostctl: %v\n", err)
				return 2
			}
			return 0
		}
		if err := hostguard.Remove(spec); err != nil {
			fmt.Fprintf(os.Stderr, "denyout hostctl: %v\n", err)
			return 2
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "denyout hostctl: unknown action %q\n", action)
		return 2
	}
}

func cmdHostctlProxyd(args []string) int {
	port := 0
	caDir := ""
	ask := false
	allowBase := ""
	controlURL := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--ask":
			ask = true
		case strings.HasPrefix(a, "--port="):
			fmt.Sscanf(strings.TrimPrefix(a, "--port="), "%d", &port)
		case a == "--port":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &port)
			}
		case strings.HasPrefix(a, "--ca-dir="):
			caDir = strings.TrimPrefix(a, "--ca-dir=")
		case a == "--ca-dir":
			i++
			if i < len(args) {
				caDir = args[i]
			}
		case strings.HasPrefix(a, "--allow-base="):
			allowBase = strings.TrimPrefix(a, "--allow-base=")
		case a == "--allow-base":
			i++
			if i < len(args) {
				allowBase = args[i]
			}
		case strings.HasPrefix(a, "--control-url="):
			controlURL = strings.TrimPrefix(a, "--control-url=")
		case a == "--control-url":
			i++
			if i < len(args) {
				controlURL = args[i]
			}
		default:
			fmt.Fprintf(os.Stderr, "denyout hostctl proxyd: unknown flag %q\n", a)
			return 2
		}
	}
	if port <= 0 || caDir == "" {
		fmt.Fprintln(os.Stderr, "denyout hostctl proxyd: --port and --ca-dir required")
		return 2
	}
	var rules []policy.Rule
	if raw := os.Getenv("DENYOUT_ALWAYS_ALLOW"); raw != "" {
		for _, h := range strings.Split(raw, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				rules = append(rules, policy.Rule{Host: h, Reason: "user_always"})
			}
		}
	}
	profile := strings.ToLower(strings.TrimSpace(os.Getenv("DENYOUT_POLICY_PROFILE")))
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
	case ask || len(rules) > 0:
		cfg, err = policy.DefaultWholeDeviceAsk(rules)
	default:
		cfg, err = policy.DefaultWholeDevice()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "denyout hostctl proxyd: %v\n", err)
		return 2
	}
	var threats policy.ThreatChecker
	if att, err := threatlists.OpenAndRefresh(context.Background(), true); err != nil {
		fmt.Fprintf(os.Stderr, "denyout hostctl proxyd: threatlists: %v (continuing)\n", err)
	} else {
		threats = att.Store
	}
	var sessRef *run.Session
	sess, err := run.StartSession(run.SessionOptions{
		Config:        cfg,
		TLSMode:       proxy.TLSIntercept,
		Version:       version,
		CADir:         caDir,
		PersistCA:     true,
		Transparent:   true,
		ListenPort:    port,
		PolicyProfile: profile,
		Process:       "proxyd",
		Threats:       threats,
		OnDeny: func(host string, reasons []string, redactedURL string) {
			hostNotAllowed := false
			for _, r := range reasons {
				if r == "host_not_allowed" {
					hostNotAllowed = true
					break
				}
			}
			// Raw IP literals: hard-deny toast only (no Ask). Control rate-limits.
			if net.ParseIP(host) != nil {
				if controlURL != "" {
					go postControlDenyEvent(controlURL, host, reasons, redactedURL, true)
					return
				}
				notify.Deny(host, reasons, redactedURL)
				return
			}
			if ask && hostNotAllowed {
				if controlURL != "" {
					// Update tray last-deny without toast; Ask dialog follows (coalesced).
					go postControlDenyEvent(controlURL, host, reasons, redactedURL, false)
					action := askViaControl(controlURL, host)
					switch action {
					case "once":
						if sessRef != nil {
							sessRef.AllowHost(host, "user_once")
						}
					case "always":
						if sessRef != nil {
							sessRef.AllowHost(host, "user_always")
						}
						postControlAlways(controlURL, host)
					}
					return
				}
				if allowBase != "" {
					u := strings.TrimRight(allowBase, "/") + "/allow.html?host=" + host
					go notify.Ask(notify.AskOptions{Host: host, OpenURL: u})
					return
				}
			}
			if controlURL != "" {
				// Tray process owns toast + LastDenySummary (avoid duplicate notify).
				go postControlDenyEvent(controlURL, host, reasons, redactedURL, true)
				return
			}
			notify.Deny(host, reasons, redactedURL)
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "denyout hostctl proxyd: %v\n", err)
		return 2
	}
	sessRef = sess
	fmt.Fprintf(os.Stderr, "denyout hostctl proxyd: listening :%d transparent\n", sess.Port())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	_ = sess.Stop()
	return 0
}

func askViaControl(base, host string) string {
	u := strings.TrimRight(base, "/") + "/ask?host=" + url.QueryEscape(host)
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(u)
	if err != nil {
		return "deny"
	}
	defer resp.Body.Close()
	var out struct {
		Action string `json:"action"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return "deny"
	}
	switch out.Action {
	case "once", "always", "deny":
		return out.Action
	default:
		return "deny"
	}
}

func postControlAlways(base, host string) {
	u := strings.TrimRight(base, "/") + "/always"
	body, _ := json.Marshal(map[string]string{"host": host})
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(u, "application/json", bytes.NewReader(body))
	if err == nil {
		resp.Body.Close()
	}
}

func postControlDenyEvent(base, host string, reasons []string, redactedURL string, doNotify bool) {
	u := strings.TrimRight(base, "/") + "/deny-event"
	body, _ := json.Marshal(map[string]any{
		"host":    host,
		"reasons": reasons,
		"url":     redactedURL,
		"notify":  doNotify,
	})
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(u, "application/json", bytes.NewReader(body))
	if err == nil {
		resp.Body.Close()
	}
}

func cmdAudit(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Println(`Usage: denyout audit tail [-n N] [--denials] [--path FILE]

  Show recent events from audit.jsonl (desktop path by default).
  --denials  only deny / would_deny
  -n N       number of events (default 50)`)
		return 0
	}
	if args[0] != "tail" {
		fmt.Fprintf(os.Stderr, "denyout audit: unknown subcommand %q (want: tail)\n", args[0])
		return 2
	}
	limit := 50
	denialsOnly := false
	path := ""
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--denials":
			denialsOnly = true
		case a == "-n" || a == "--limit":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout audit tail: -n requires a number")
				return 2
			}
			n, err := strconv.Atoi(args[i])
			if err != nil || n <= 0 {
				fmt.Fprintf(os.Stderr, "denyout audit tail: invalid -n %q\n", args[i])
				return 2
			}
			limit = n
		case a == "--path":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout audit tail: --path requires a file")
				return 2
			}
			path = args[i]
		case a == "--help" || a == "-h":
			return cmdAudit(nil)
		default:
			fmt.Fprintf(os.Stderr, "denyout audit tail: unknown flag %q\n", a)
			return 2
		}
	}
	if path == "" {
		path = desktop.AuditLogPath()
	}
	events, err := audit.TailEvents(path, limit, denialsOnly)
	if err != nil {
		fmt.Fprintf(os.Stderr, "denyout audit tail: %v\n", err)
		return 1
	}
	if len(events) == 0 {
		fmt.Fprintln(os.Stderr, "denyout audit tail: no events")
		return 0
	}
	enc := json.NewEncoder(os.Stdout)
	for _, ev := range events {
		_ = enc.Encode(ev)
	}
	return 0
}

func cmdDesktop(args []string) int {
	cfgPath := ""
	forceSetup := false
	noTray := false
	noOpen := false
	webUI := false
	doInstall := false
	listen := "127.0.0.1:0"

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--help" || a == "-h":
			fmt.Println(`Usage: denyout desktop [--install] [--setup] [--no-tray] [--web-ui] [--no-open] [--config path]

  Default: tray + restore protection from state (no browser UI).
  Scopes: whole computer (hostguard, admin) or session (HTTP proxy env, no admin).

  --install  silent setup: autostart, try computer once, fallback session, detach tray
  --web-ui   optional localhost settings page (tests / advanced only)
  --no-open  with --web-ui, do not open a browser
  --setup    mark first-run done (silent defaults)

  Install: install.sh → denyout desktop --install on Desktop machines.`)
			return 0
		case a == "--install":
			doInstall = true
		case a == "--setup":
			forceSetup = true
		case a == "--no-tray":
			noTray = true
		case a == "--no-open":
			noOpen = true
		case a == "--web-ui":
			webUI = true
		case a == "--config" || a == "-c":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout desktop: --config requires a path")
				return 2
			}
			cfgPath = args[i]
		case strings.HasPrefix(a, "--listen="):
			listen = strings.TrimPrefix(a, "--listen=")
			webUI = true
		case a == "--listen":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout desktop: --listen requires a value")
				return 2
			}
			listen = args[i]
			webUI = true
		default:
			fmt.Fprintf(os.Stderr, "denyout desktop: unknown flag %q\n", a)
			return 2
		}
	}

	if doInstall {
		if err := desktop.Install(desktop.Options{ConfigPath: cfgPath, Version: version}); err != nil {
			fmt.Fprintf(os.Stderr, "denyout desktop --install: %v\n", err)
			return 2
		}
		return 0
	}

	if webUI {
		if !strings.HasPrefix(listen, "127.0.0.1:") && !strings.HasPrefix(listen, "localhost:") {
			fmt.Fprintln(os.Stderr, "denyout desktop: --listen must be 127.0.0.1 or localhost")
			return 2
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := desktop.Run(ctx, desktop.Options{
		ConfigPath: cfgPath,
		Version:    version,
		ForceSetup: forceSetup,
		NoTray:     noTray,
		NoOpen:     noOpen,
		WebUI:      webUI,
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
	quiet := false
	metrics := false
	var corpusJSONL []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--help" || a == "-h":
			fmt.Println("Usage: denyout test [--db path] [--suite name] [--corpus-jsonl path]... [--quiet] [--metrics]")
			fmt.Println("  Seeds the lab DB if needed, runs active fixtures (no network dial).")
			fmt.Println("  --corpus-jsonl  import external JSONL cases (Prowl / egress-bench) before run")
			fmt.Println("  --quiet         print summary only (needed for large corpora)")
			fmt.Println("  --metrics       print TP/FP/TN/FN precision/recall (deny = positive class)")
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
		case a == "--corpus-jsonl":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "denyout test: --corpus-jsonl requires a path")
				return 2
			}
			corpusJSONL = append(corpusJSONL, args[i])
		case strings.HasPrefix(a, "--corpus-jsonl="):
			corpusJSONL = append(corpusJSONL, strings.TrimPrefix(a, "--corpus-jsonl="))
		case a == "--quiet":
			quiet = true
		case a == "--metrics":
			metrics = true
		default:
			fmt.Fprintf(os.Stderr, "denyout test: unknown flag %q\n", a)
			return 2
		}
	}

	if len(corpusJSONL) > 0 && dbPath == "examples/fixtures/denyout-lab.sqlite" {
		dbPath = "examples/fixtures/denyout-lab-corpus.sqlite"
	}

	var db *sql.DB
	var err error
	if len(corpusJSONL) > 0 {
		db, err = lab.Open(dbPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "denyout test: %v\n", err)
			return 2
		}
		for _, p := range corpusJSONL {
			n, err := lab.SeedJSONL(db, p)
			if err != nil {
				_ = db.Close()
				fmt.Fprintf(os.Stderr, "denyout test: import %s: %v\n", p, err)
				return 2
			}
			fmt.Fprintf(os.Stderr, "denyout test: imported %d cases from %s\n", n, p)
		}
	} else {
		db, err = lab.OpenSeeded(dbPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "denyout test: %v\n", err)
			return 2
		}
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

	if !quiet {
		for _, r := range rep.Results {
			status := "PASS"
			if !r.Passed {
				status = "FAIL"
			}
			fmt.Printf("%s %s suite=%s verdict=%s reasons=%v %s\n", status, r.CaseID, r.Suite, r.Verdict, r.Reasons, r.Detail)
		}
	}
	fmt.Printf("summary run_id=%s passed=%d failed=%d total=%d db=%s\n", rep.RunID, rep.Passed, rep.Failed, rep.Total, dbPath)
	if metrics || len(corpusJSONL) > 0 {
		m := lab.MetricsFromResults(rep.Results)
		fmt.Printf("metrics tp=%d fp=%d tn=%d fn=%d precision=%.4f recall=%.4f specificity=%.4f\n",
			m.TP, m.FP, m.TN, m.FN, m.Precision(), m.Recall(), m.Specificity())
	}
	if len(corpusJSONL) > 0 {
		// Large external corpora are yardsticks (metrics), not hard CI gates.
		return 0
	}
	if rep.Failed > 0 {
		return 1
	}
	return 0
}
