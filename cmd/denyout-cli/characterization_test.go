package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/tun"
)

// Characterization tests: pin the observable CLI behaviour (exit code, stdout,
// stderr) of argument parsing / validation so the per-command refactor cannot
// change flags, exit codes or text. Only paths that touch no host state.

type charCase struct {
	name   string
	args   []string
	code   int
	out    string // exact stdout unless outHas is set
	err    string // exact stderr
	outHas []string
}

func runChar(t *testing.T, cases []charCase) {
	t.Helper()
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			code, out, errS := capture(t, func() int { return runMain(c.args) })
			if code != c.code {
				t.Fatalf("code=%d want %d (out=%q err=%q)", code, c.code, out, errS)
			}
			if c.outHas != nil {
				for _, s := range c.outHas {
					if !strings.Contains(out, s) {
						t.Errorf("stdout missing %q in %q", s, out)
					}
				}
			} else if out != c.out {
				t.Errorf("stdout=%q want %q", out, c.out)
			}
			if errS != c.err {
				t.Errorf("stderr=%q want %q", errS, c.err)
			}
		})
	}
}

func TestCharMainDispatch(t *testing.T) {
	code, _, errS := capture(t, func() int { return runMain(nil) })
	if code != 2 || !strings.HasPrefix(errS, "denyout-cli — free egress seatbelt") {
		t.Fatalf("no args: %d %q", code, errS)
	}
	code, _, errS = capture(t, func() int { return runMain([]string{"bogus"}) })
	if code != 2 || !strings.HasPrefix(errS, "denyout-cli: unknown command \"bogus\"\n\ndenyout-cli — free") {
		t.Fatalf("unknown: %d %q", code, errS)
	}
	for _, a := range []string{"help", "--help", "-h"} {
		code, out, _ := capture(t, func() int { return runMain([]string{a}) })
		if code != 0 || !strings.Contains(out, "Usage:\n  denyout-cli <command> [arguments]") || !strings.HasSuffix(out, "docs in this repo.\n") {
			t.Fatalf("%s: %d %q", a, code, out)
		}
	}
	for _, a := range []string{"version", "--version", "-V"} {
		code, out, _ := capture(t, func() int { return runMain([]string{a}) })
		if code != 0 || out != "denyout-cli "+version+"\n" {
			t.Fatalf("%s: %d %q", a, code, out)
		}
	}
}

func TestCharCheck(t *testing.T) {
	runChar(t, []charCase{
		{name: "help", args: []string{"check", "-h"}, out: "Usage: denyout-cli check [--config path] [--json] <url>\n"},
		{name: "nourl", args: []string{"check"}, code: 2, err: "denyout-cli check: URL required\n"},
		{name: "unknown", args: []string{"check", "--bogus"}, code: 2, err: "denyout-cli check: unknown flag \"--bogus\"\n"},
		{name: "two", args: []string{"check", "a", "b"}, code: 2, err: "denyout-cli check: only one URL allowed\n"},
		{name: "cfgmissing", args: []string{"check", "-c"}, code: 2, err: "denyout-cli check: --config requires a path\n"},
		{name: "cfgmissing-long", args: []string{"check", "--json", "--config"}, code: 2, err: "denyout-cli check: --config requires a path\n"},
		{name: "helpafterurl", args: []string{"check", "http://x", "--help"}, out: "Usage: denyout-cli check [--config path] [--json] <url>\n"},
		{name: "badcfg", args: []string{"check", "-c", "/nonexistent/x.yaml", "https://example.com"}, code: 2, err: "denyout-cli check: config: open /nonexistent/x.yaml: no such file or directory\n"},
	})
	code, out, _ := capture(t, func() int { return runMain([]string{"check", "http://127.0.0.1/"}) })
	if code != 1 || !strings.Contains(out, "deny") {
		t.Fatalf("deny: %d %q", code, out)
	}
	code, out, _ = capture(t, func() int { return runMain([]string{"check", "--json", "http://127.0.0.1/"}) })
	if code != 1 || !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Fatalf("deny json: %d %q", code, out)
	}
	code, out, _ = capture(t, func() int { return runMain([]string{"check", "https://api.anthropic.com/v1/messages"}) })
	if code != 0 || out == "" {
		t.Fatalf("allow: %d %q", code, out)
	}
}

func TestCharPolicyConfigInit(t *testing.T) {
	runChar(t, []charCase{
		{name: "policy-usage", args: []string{"policy"}, code: 2, err: "Usage: denyout-cli policy check <file>\n"},
		{name: "policy-usage2", args: []string{"policy", "x"}, code: 2, err: "Usage: denyout-cli policy check <file>\n"},
		{name: "policy-nofile", args: []string{"policy", "validate"}, code: 2, err: "denyout-cli policy validate: file required\n"},
		{name: "policy-missing", args: []string{"policy", "check", "/nonexistent/p"}, code: 2, err: "denyout-cli policy check: open /nonexistent/p: no such file or directory\n"},
		{name: "config-usage", args: []string{"config"}, code: 2, err: "Usage: denyout-cli config show [--json]\n"},
		{name: "config-badflag", args: []string{"config", "show", "--x"}, code: 2, err: "denyout-cli config show: unknown flag \"--x\"\n"},
	})
	dir := t.TempDir()
	p := filepath.Join(dir, "d.yaml")
	bad := filepath.Join(dir, "no", "x.yaml")
	runChar(t, []charCase{
		{name: "init-help", args: []string{"init", "--help"}, out: "Usage: denyout-cli init [path]\n"},
		{name: "init-ok", args: []string{"init", p}, out: "wrote " + p + "\n"},
		{name: "init-exists", args: []string{"init", p}, code: 2, err: "denyout-cli init: " + p + " already exists\n"},
		{name: "init-badpath", args: []string{"init", bad}, code: 2, err: "denyout-cli init: open " + bad + ": no such file or directory\n"},
	})
	b, _ := os.ReadFile(p)
	if !strings.HasPrefix(string(b), "apiVersion: denyout/v1\nkind: Config\n") || !strings.HasSuffix(string(b), "stdout: false\n") {
		t.Fatalf("init content: %q", b)
	}
	runChar(t, []charCase{{name: "init-validates", args: []string{"policy", "check", p}, out: "ok\n"}})
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	_ = os.Chdir(dir)
	runChar(t, []charCase{{name: "init-default", args: []string{"init", "--whatever"}, out: "wrote denyout.yaml\n"}})
}

func TestCharRunParse(t *testing.T) {
	runChar(t, []charCase{
		{name: "help", args: []string{"run", "-h"}, out: "Usage: denyout-cli run [--config path] [--profile id] [--tls-mode intercept|passthrough] [--sandbox=srt] [--notify|--no-notify] -- <command>...\n"},
		{name: "nocmd", args: []string{"run"}, code: 2, err: "denyout-cli run: missing -- <command> (or --profile with a command)\n"},
		{name: "unknown", args: []string{"run", "--x", "--", "true"}, code: 2, err: "denyout-cli run: unknown flag \"--x\" (command must follow --)\n"},
		{name: "positional", args: []string{"run", "true"}, code: 2, err: "denyout-cli run: unknown flag \"true\" (command must follow --)\n"},
		{name: "cfg", args: []string{"run", "-c"}, code: 2, err: "denyout-cli run: --config requires a path\n"},
		{name: "profile", args: []string{"run", "--profile"}, code: 2, err: "denyout-cli run: --profile requires an id\n"},
		{name: "tls", args: []string{"run", "--tls-mode"}, code: 2, err: "denyout-cli run: --tls-mode requires a value\n"},
		{name: "sandbox", args: []string{"run", "--sandbox"}, code: 2, err: "denyout-cli run: --sandbox requires a value\n"},
		{name: "badtls", args: []string{"run", "--tls-mode=x", "--", "true"}, code: 2, err: "denyout-cli run: invalid tls-mode \"x\"\n"},
		{name: "badtls2", args: []string{"run", "--tls-mode", "off", "--", "true"}, code: 2, err: "denyout-cli run: invalid tls-mode \"off\"\n"},
		{name: "nocmd-flags", args: []string{"run", "--no-notify", "--notify", "--sandbox=srt", "--"}, code: 2, err: "denyout-cli run: missing -- <command> (or --profile with a command)\n"},
	})
	isolate(t)
	code, _, errS := capture(t, func() int { return runMain([]string{"run", "--profile=nope", "--", "true"}) })
	if code != 2 || !strings.HasPrefix(errS, "denyout-cli run: profile: ") {
		t.Fatalf("profile missing: %d %q", code, errS)
	}
	code, _, errS = capture(t, func() int { return runMain([]string{"profile", "run", "nope"}) })
	if code != 2 || !strings.HasPrefix(errS, "denyout-cli run: profile: ") {
		t.Fatalf("profile run: %d %q", code, errS)
	}
}

func TestCharProfile(t *testing.T) {
	isolate(t)
	runChar(t, []charCase{
		{name: "none", args: []string{"profile"}, outHas: []string{"Usage: denyout-cli profile <command>", "Profiles live in ~/.config/denyout/profiles/"}},
		{name: "help", args: []string{"profile", "-h"}, outHas: []string{"discard <id>                 Discard pending Once hosts"}},
		{name: "unknown", args: []string{"profile", "zap"}, code: 2, err: "denyout-cli profile: unknown \"zap\"\n"},
		{name: "list-empty", args: []string{"profile", "list"}, out: "(no profiles)\n"},
		{name: "create-noname", args: []string{"profile", "create", "--", "x"}, code: 2, err: "denyout-cli profile create: need --name and -- <command>\n"},
		{name: "create-nocmd", args: []string{"profile", "create", "--name", "a"}, code: 2, err: "denyout-cli profile create: need --name and -- <command>\n"},
		{name: "create-flag", args: []string{"profile", "create", "--zz", "--", "x"}, code: 2, err: "denyout-cli profile create: unknown flag \"--zz\"\n"},
		{name: "show-noid", args: []string{"profile", "show"}, code: 2, err: "denyout-cli profile show: need id\n"},
		{name: "delete-noid", args: []string{"profile", "delete"}, code: 2, err: "denyout-cli profile delete: need id\n"},
		{name: "run-noid", args: []string{"profile", "run"}, code: 2, err: "denyout-cli profile run: need id\n"},
		{name: "pin-noid", args: []string{"profile", "pin"}, code: 2, err: "denyout-cli profile pin: need id\n"},
		{name: "discard-noid", args: []string{"profile", "discard"}, code: 2, err: "denyout-cli profile discard: need id\n"},
		{name: "export-usage", args: []string{"profile", "export", "a"}, code: 2, err: "Usage: denyout-cli profile export <id> <file>\n"},
		{name: "import-usage", args: []string{"profile", "import", "--force", "a"}, code: 2, err: "Usage: denyout-cli profile import [--force] <id> <file>\n"},
	})
	code, out, errS := capture(t, func() int { return runMain([]string{"profile", "create", "--name=My Agent", "--", "echo", "hi"}) })
	if code != 0 || !strings.HasPrefix(out, "created ") || errS != "" {
		t.Fatalf("create: %d %q %q", code, out, errS)
	}
	id := strings.Fields(strings.TrimPrefix(out, "created "))[0]
	code, out, _ = capture(t, func() int { return runMain([]string{"profile", "list"}) })
	if code != 0 || !strings.HasPrefix(out, id+"\tMy Agent\t") || !strings.HasSuffix(out, "\tpending=0\n") {
		t.Fatalf("list: %d %q", code, out)
	}
	code, out, _ = capture(t, func() int { return runMain([]string{"profile", "show", id}) })
	if code != 0 || !strings.HasPrefix(out, "id="+id+" name=\"My Agent\" preset=") || !strings.Contains(out, "\npath=") {
		t.Fatalf("show: %d %q", code, out)
	}
	code, out, _ = capture(t, func() int { return runMain([]string{"profile", "pin", id}) })
	if code != 0 || out != "pinned 0 host(s); learning off\n" {
		t.Fatalf("pin: %d %q", code, out)
	}
	code, out, _ = capture(t, func() int { return runMain([]string{"profile", "discard", id}) })
	if code != 0 || out != "discarded pending\n" {
		t.Fatalf("discard: %d %q", code, out)
	}
	f := filepath.Join(t.TempDir(), "exp.yaml")
	code, out, _ = capture(t, func() int { return runMain([]string{"profile", "export", id, f}) })
	if code != 0 || out != "exported "+id+" to "+f+"\n" {
		t.Fatalf("export: %d %q", code, out)
	}
	code, out, _ = capture(t, func() int { return runMain([]string{"profile", "import", "--force", "copy1", f}) })
	if code != 0 || !strings.HasPrefix(out, "imported ") {
		t.Fatalf("import: %d %q", code, out)
	}
	code, out, _ = capture(t, func() int { return runMain([]string{"profile", "delete", id}) })
	if code != 0 || out != "deleted "+id+"\n" {
		t.Fatalf("delete: %d %q", code, out)
	}
	for _, sub := range []string{"show", "delete", "pin", "discard"} {
		code, _, errS = capture(t, func() int { return runMain([]string{"profile", sub, id}) })
		if code != 2 || !strings.HasPrefix(errS, "denyout-cli profile "+sub+": ") {
			t.Fatalf("%s gone: %d %q", sub, code, errS)
		}
	}
	code, _, errS = capture(t, func() int { return runMain([]string{"profile", "export", id, f}) })
	if code != 2 || !strings.HasPrefix(errS, "denyout-cli profile export: ") {
		t.Fatalf("export gone: %d %q", code, errS)
	}
	code, _, errS = capture(t, func() int { return runMain([]string{"profile", "import", "x", "/nonexistent/f"}) })
	if code != 2 || !strings.HasPrefix(errS, "denyout-cli profile import: ") {
		t.Fatalf("import bad: %d %q", code, errS)
	}
}

func vpnPlanErr(t *testing.T) string {
	t.Helper()
	_, err := tun.FormatVPNEgressPlan("")
	if err == nil {
		t.Fatal("expected error for empty iface")
	}
	return err.Error()
}

func TestCharHostctlSafe(t *testing.T) {
	code, out, _ := capture(t, func() int { return runMain([]string{"hostctl"}) })
	if code != 0 || !strings.HasPrefix(out, "Usage: denyout-cli hostctl apply|remove|teardown|render|proxyd|") ||
		!strings.HasSuffix(out, "  --no-elevate already running elevated (internal)\n") {
		t.Fatalf("help: %d %q", code, out)
	}
	runChar(t, []charCase{
		{name: "unknown-action", args: []string{"hostctl", "zap"}, code: 2, err: "denyout-cli hostctl: unknown action \"zap\"\n"},
		{name: "unknown-flag", args: []string{"hostctl", "zap", "--x"}, code: 2, err: "denyout-cli hostctl: unknown flag \"--x\"\n"},
		{name: "apply-badpolicy", args: []string{"hostctl", "apply", "--fail-policy=maybe"}, code: 2, err: "denyout-cli hostctl: --fail-policy must be open or closed\n"},
		{name: "apply-badpolicy2", args: []string{"hostctl", "apply", "--fail-policy", "x", "--no-elevate"}, code: 2, err: "denyout-cli hostctl: --fail-policy must be open or closed\n"},
		{name: "failpolicy-usage", args: []string{"hostctl", "fail-policy"}, code: 2, err: "Usage: denyout-cli hostctl fail-policy open|closed|status\n"},
		{name: "failpolicy-usage2", args: []string{"hostctl", "fail-policy", "maybe"}, code: 2, err: "Usage: denyout-cli hostctl fail-policy open|closed|status\n"},
		{name: "failpolicy-usage3", args: []string{"hostctl", "fail-policy", "open", "x"}, code: 2, err: "Usage: denyout-cli hostctl fail-policy open|closed|status\n"},
		{name: "vpn-apply-gated", args: []string{"hostctl", "vpn-egress-apply", "--iface", "wg0"}, code: 2, err: "denyout-cli hostctl vpn-egress-apply: set DENYOUT_VPN_EGRESS_E2E=1 (VM only)\n"},
		{name: "vpn-plan-noiface", args: []string{"hostctl", "vpn-egress-plan"}, code: 2, err: "denyout-cli hostctl vpn-egress-plan: " + vpnPlanErr(t) + "\n"},
	})
	for _, a := range []string{"tun-rollback-plan", "tun-device-plan", "tun-device-rollback-plan", "vpn-egress-rollback-plan"} {
		code, out, errS := capture(t, func() int { return runMain([]string{"hostctl", a}) })
		if code != 0 || out == "" || errS != "" {
			t.Fatalf("%s: %d %q %q", a, code, out, errS)
		}
	}
	code, out, _ = capture(t, func() int { return runMain([]string{"hostctl", "vpn-egress-plan", "--iface=wg0"}) })
	if code != 0 || !strings.Contains(out, "wg0") {
		t.Fatalf("vpn plan: %d %q", code, out)
	}
	code, out, _ = capture(t, func() int {
		return runMain([]string{"hostctl", "render", "--port", "8080", "--uid=1000", "--ca", "/x.pem", "--allow-quic"})
	})
	if code != 0 || out == "" {
		t.Fatalf("render: %d %q", code, out)
	}
	code, out2, _ := capture(t, func() int {
		return runMain([]string{"hostctl", "render", "--port=8080", "--uid", "1000", "--ca=/x.pem", "--allow-quic", "--tun"})
	})
	if code != 0 || !strings.Contains(out2, "T1 TUN preview") {
		t.Fatalf("render tun: %d %q", code, out2)
	}
}

func TestCharProxydParse(t *testing.T) {
	const req = "denyout-cli hostctl proxyd: --port and --ca-dir required\n"
	runChar(t, []charCase{
		{name: "unknown", args: []string{"hostctl", "proxyd", "--x"}, code: 2, err: "denyout-cli hostctl proxyd: unknown flag \"--x\"\n"},
		{name: "noport", args: []string{"hostctl", "proxyd", "--ca-dir", "/x"}, code: 2, err: req},
		{name: "nocadir", args: []string{"hostctl", "proxyd", "--port=5"}, code: 2, err: req},
		{name: "badport", args: []string{"hostctl", "proxyd", "--port=abc", "--ca-dir=/x"}, code: 2, err: req},
		{name: "neg", args: []string{"hostctl", "proxyd", "--port", "-3", "--ca-dir", "/x"}, code: 2, err: req},
		{name: "flags-missing-vals", args: []string{"hostctl", "proxyd", "--ask", "--allow-base", "--control-url"}, code: 2, err: req},
	})
}

func TestCharMisc(t *testing.T) {
	runChar(t, []charCase{
		{name: "uninstall-help", args: []string{"uninstall", "-h"}, outHas: []string{"Usage: denyout-cli uninstall [--keep-config] [--yes]", "keeps CA/hostguard for one Apply."}},
		{name: "uninstall-flag", args: []string{"uninstall", "--x"}, code: 2, err: "denyout-cli uninstall: unknown flag \"--x\"\n"},
		{name: "audit-help", args: []string{"audit"}, outHas: []string{"Usage: denyout-cli audit tail [-n N] [--denials] [--path FILE]", "-n N       number of events (default 50)"}},
		{name: "audit-help2", args: []string{"audit", "-h"}, outHas: []string{"--denials  only deny / would_deny"}},
		{name: "audit-sub", args: []string{"audit", "zap"}, code: 2, err: "denyout-cli audit: unknown subcommand \"zap\" (want: tail)\n"},
		{name: "audit-n-missing", args: []string{"audit", "tail", "-n"}, code: 2, err: "denyout-cli audit tail: -n requires a number\n"},
		{name: "audit-n-bad", args: []string{"audit", "tail", "-n", "x"}, code: 2, err: "denyout-cli audit tail: invalid -n \"x\"\n"},
		{name: "audit-n-zero", args: []string{"audit", "tail", "--limit", "0"}, code: 2, err: "denyout-cli audit tail: invalid -n \"0\"\n"},
		{name: "audit-path-missing", args: []string{"audit", "tail", "--path"}, code: 2, err: "denyout-cli audit tail: --path requires a file\n"},
		{name: "audit-flag", args: []string{"audit", "tail", "--x"}, code: 2, err: "denyout-cli audit tail: unknown flag \"--x\"\n"},
		{name: "audit-help-in-tail", args: []string{"audit", "tail", "-h"}, outHas: []string{"Usage: denyout-cli audit tail"}},
		{name: "audit-none", args: []string{"audit", "tail", "--path", "/nonexistent/a.jsonl"}, err: "denyout-cli audit tail: no events\n"},
		{name: "desktop-help", args: []string{"desktop", "-h"}, outHas: []string{"Usage: denyout-cli desktop [--install]", "Install: install.sh → denyout-cli desktop --install on Desktop machines."}},
		{name: "desktop-cfg", args: []string{"desktop", "-c"}, code: 2, err: "denyout-cli desktop: --config requires a path\n"},
		{name: "desktop-listen", args: []string{"desktop", "--listen"}, code: 2, err: "denyout-cli desktop: --listen requires a value\n"},
		{name: "desktop-flag", args: []string{"desktop", "--x"}, code: 2, err: "denyout-cli desktop: unknown flag \"--x\"\n"},
		{name: "desktop-nonlocal", args: []string{"desktop", "--listen=0.0.0.0:1"}, code: 2, err: "denyout-cli desktop: --listen must be 127.0.0.1 or localhost\n"},
		{name: "desktop-nonlocal2", args: []string{"desktop", "--web-ui", "--listen", "example.com:1"}, code: 2, err: "denyout-cli desktop: --listen must be 127.0.0.1 or localhost\n"},
		{name: "serve-help", args: []string{"serve", "-h"}, outHas: []string{"Usage: denyout-cli serve --config path", "DENYOUT_KILL=1 refuses to start (fail closed)."}},
		{name: "serve-nocfg", args: []string{"serve"}, code: 2, err: "denyout-cli serve: --config is required\n"},
		{name: "serve-flag", args: []string{"serve", "--x"}, code: 2, err: "denyout-cli serve: unknown flag \"--x\"\n"},
		{name: "serve-cfg", args: []string{"serve", "-c"}, code: 2, err: "denyout-cli serve: --config requires a path\n"},
		{name: "serve-listen", args: []string{"serve", "--listen"}, code: 2, err: "denyout-cli serve: --listen requires a value\n"},
		{name: "serve-metrics", args: []string{"serve", "--metrics-listen"}, code: 2, err: "denyout-cli serve: --metrics-listen requires a value\n"},
		{name: "serve-health", args: []string{"serve", "--health-listen"}, code: 2, err: "denyout-cli serve: --health-listen requires a value\n"},
		{name: "serve-tls", args: []string{"serve", "--tls-mode"}, code: 2, err: "denyout-cli serve: --tls-mode requires a value\n"},
		{name: "serve-cadir", args: []string{"serve", "--ca-dir"}, code: 2, err: "denyout-cli serve: --ca-dir requires a path\n"},
		{name: "serve-badtls", args: []string{"serve", "-c", "x", "--tls-mode=zz"}, code: 2, err: "denyout-cli serve: invalid tls-mode \"zz\"\n"},
		{name: "gui-help", args: []string{"gui", "-h"}, out: "Usage: denyout-cli gui [--config path] [--tls-mode intercept|passthrough] [--listen 127.0.0.1:0] [--no-open]\n  Localhost web UI: start/stop wrap, mode/preset, check URL, recent redacted denials.\n  Same policy engine as CLI; does not bypass denyout-cli run.\n"},
		{name: "gui-cfg", args: []string{"gui", "-c"}, code: 2, err: "denyout-cli gui: --config requires a path\n"},
		{name: "gui-tls", args: []string{"gui", "--tls-mode"}, code: 2, err: "denyout-cli gui: --tls-mode requires a value\n"},
		{name: "gui-listen", args: []string{"gui", "--listen"}, code: 2, err: "denyout-cli gui: --listen requires a value\n"},
		{name: "gui-flag", args: []string{"gui", "--x"}, code: 2, err: "denyout-cli gui: unknown flag \"--x\"\n"},
		{name: "gui-badtls", args: []string{"gui", "--tls-mode=q"}, code: 2, err: "denyout-cli gui: invalid tls-mode \"q\"\n"},
		{name: "gui-nonlocal", args: []string{"gui", "--listen=0.0.0.0:1"}, code: 2, err: "denyout-cli gui: --listen must be 127.0.0.1 or localhost (desktop UI is local-only)\n"},
		{name: "test-help", args: []string{"test", "-h"}, out: "Usage: denyout-cli test [--db path] [--suite name] [--corpus-jsonl path]... [--quiet] [--metrics]\n  Seeds the lab DB if needed, runs active fixtures (no network dial).\n  --corpus-jsonl  import external JSONL cases (Prowl / egress-bench) before run\n  --quiet         print summary only (needed for large corpora)\n  --metrics       print TP/FP/TN/FN precision/recall (deny = positive class)\n"},
		{name: "test-db", args: []string{"test", "--db"}, code: 2, err: "denyout-cli test: --db requires a path\n"},
		{name: "test-suite", args: []string{"test", "--suite"}, code: 2, err: "denyout-cli test: --suite requires a name\n"},
		{name: "test-corpus", args: []string{"test", "--corpus-jsonl"}, code: 2, err: "denyout-cli test: --corpus-jsonl requires a path\n"},
		{name: "test-flag", args: []string{"test", "--x"}, code: 2, err: "denyout-cli test: unknown flag \"--x\"\n"},
	})
}

func TestCharLabTest(t *testing.T) {
	db := filepath.Join(t.TempDir(), "lab.sqlite")
	code, out, errS := capture(t, func() int { return runMain([]string{"test", "--db=" + db, "--quiet", "--metrics"}) })
	if errS != "" || (code != 0 && code != 1) || !strings.HasPrefix(out, "summary run_id=") || !strings.Contains(out, " db="+db+"\nmetrics tp=") {
		t.Fatalf("lab: %d out=%q err=%q", code, out, errS)
	}
	code, out, _ = capture(t, func() int { return runMain([]string{"test", "--db", db, "--suite=r20_url"}) })
	if (code != 0 && code != 1) || !strings.Contains(out, "PASS ") || !strings.Contains(out, "\nsummary run_id=") {
		t.Fatalf("lab suite: %d %q", code, out)
	}
	code, _, errS = capture(t, func() int {
		return runMain([]string{"test", "--db", db, "--suite", "r20_url", "--corpus-jsonl=/nonexistent.jsonl"})
	})
	if code != 2 || !strings.HasPrefix(errS, "denyout-cli test: ") {
		t.Fatalf("lab corpus: %d %q", code, errS)
	}
	code, _, errS = capture(t, func() int { return runMain([]string{"test", "--db", filepath.Join(write(t, "x"), "x.sqlite")}) })
	if code != 2 || !strings.HasPrefix(errS, "denyout-cli test: ") {
		t.Fatalf("lab baddb: %d %q", code, errS)
	}
}

func TestCharAuditTail(t *testing.T) {
	p := write(t, `{"event_id":"a","verdict":"allow"}`+"\n"+`{"event_id":"b","verdict":"deny"}`+"\n"+`{"event_id":"c","verdict":"would_deny"}`+"\n")
	code, out, _ := capture(t, func() int { return runMain([]string{"audit", "tail", "--path", p}) })
	if code != 0 || strings.Count(out, "\n") != 3 || !strings.HasPrefix(out, `{`) {
		t.Fatalf("all: %d %q", code, out)
	}
	code, out, _ = capture(t, func() int { return runMain([]string{"audit", "tail", "--path", p, "--denials"}) })
	if code != 0 || strings.Count(out, "\n") != 1 {
		t.Fatalf("denials: %d %q", code, out)
	}
	code, out, _ = capture(t, func() int { return runMain([]string{"audit", "tail", "-n", "1", "--path", p}) })
	if code != 0 || strings.Count(out, "\n") != 1 || !strings.Contains(out, `"c"`) {
		t.Fatalf("n1: %d %q", code, out)
	}
	code, _, errS := capture(t, func() int { return runMain([]string{"audit", "tail", "--path", t.TempDir()}) })
	if code != 1 || !strings.HasPrefix(errS, "denyout-cli audit tail: ") {
		t.Fatalf("dir: %d %q", code, errS)
	}
}
