package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/desktop"
	"github.com/nareyko/denyout/internal/gui"
	"github.com/nareyko/denyout/internal/proxy"
	"github.com/nareyko/denyout/internal/run"
	"github.com/nareyko/denyout/internal/serve"
)

type (
	runOptionsT = run.Options
	guiOptionsT = gui.Options
	auditEventT = audit.Event
)

func noEnv(string) string { return "" }

func wantExit(t *testing.T, ex *cliExit, code int, out, errS string) {
	t.Helper()
	if ex == nil {
		t.Fatalf("want exit %d, got nil", code)
	}
	if ex.code != code || ex.out != out || ex.err != errS {
		t.Fatalf("exit = {%d %q %q}, want {%d %q %q}", ex.code, ex.out, ex.err, code, out, errS)
	}
}

func TestFlagSetBehaviour(t *testing.T) {
	var s, pos string
	var n int
	b := false
	mk := func() *flagSet {
		s, pos, n, b = "", "", 0, false
		return &flagSet{
			cmd:  "x",
			help: "HELP",
			values: []flagSpec{
				{names: []string{"--s", "-s"}, eq: true, set: setStr(&s), missing: "--s needs value"},
				{names: []string{"--n"}, eq: true, set: setInt(&n)},
				{names: []string{"--bad"}, set: func(v string) string { return "bad " + v }},
			},
			bools:      map[string]func(){"--b": func() { b = true }},
			unknown:    "unknown flag %q",
			positional: func(a string) string { pos = a; return "" },
		}
	}
	if ex := mk().parse([]string{"--s=1", "--b", "p", "--n", "12abc"}); ex != nil || s != "1" || !b || pos != "p" || n != 12 {
		t.Fatalf("basic: %v %q %v %q %d", ex, s, b, pos, n)
	}
	if ex := mk().parse([]string{"-s", "--b"}); ex != nil || s != "--b" || b {
		t.Fatalf("value consumes next arg: %v %q %v", ex, s, b)
	}
	wantExit(t, mk().parse([]string{"--s"}), 2, "", "denyout-cli x: --s needs value\n")
	if ex := mk().parse([]string{"--n"}); ex != nil || n != 0 {
		t.Fatalf("lenient dangling: %v %d", ex, n)
	}
	wantExit(t, mk().parse([]string{"--zz"}), 2, "", "denyout-cli x: unknown flag \"--zz\"\n")
	wantExit(t, mk().parse([]string{"-h", "--zz"}), 0, "HELP\n", "")
	wantExit(t, mk().parse([]string{"--zz", "-h"}), 2, "", "denyout-cli x: unknown flag \"--zz\"\n")
	wantExit(t, mk().parse([]string{"--bad", "q"}), 2, "", "denyout-cli x: bad q\n")
}

func TestFlagSetPositionalAndIgnore(t *testing.T) {
	fs := flagSet{cmd: "y", positional: func(a string) string { return "no " + a }}
	wantExit(t, fs.parse([]string{"a"}), 2, "", "denyout-cli y: no a\n")
	if ex := fs.parse([]string{"-zz"}); ex != nil {
		t.Fatalf("unknown flags are ignored when unknown==\"\": %v", ex)
	}
}

func TestSplitDash(t *testing.T) {
	f, c := splitDash([]string{"a", "--", "b", "--", "c"})
	if !reflect.DeepEqual(f, []string{"a"}) || !reflect.DeepEqual(c, []string{"b", "--", "c"}) {
		t.Fatalf("%v %v", f, c)
	}
	f, c = splitDash([]string{"a"})
	if len(f) != 1 || c != nil {
		t.Fatalf("%v %v", f, c)
	}
}

func TestLocalListen(t *testing.T) {
	for a, want := range map[string]bool{"127.0.0.1:0": true, "localhost:9": true, "0.0.0.0:1": false, "127.0.0.1": false, "": false} {
		if localListen(a) != want {
			t.Errorf("localListen(%q) != %v", a, want)
		}
	}
}

func TestParseCheckArgs(t *testing.T) {
	o, ex := parseCheckArgs([]string{"--json", "-c", "p.yaml", "https://x"})
	if ex != nil || o != (checkOpts{cfgPath: "p.yaml", url: "https://x", jsonOut: true}) {
		t.Fatalf("%+v %v", o, ex)
	}
	_, ex = parseCheckArgs(nil)
	wantExit(t, ex, 2, "", "denyout-cli check: URL required\n")
	_, ex = parseCheckArgs([]string{"-"})
	wantExit(t, ex, 2, "", "denyout-cli check: unknown flag \"-\"\n")
}

func TestEvalCheck(t *testing.T) {
	ex := evalCheck(checkOpts{url: "http://127.0.0.1/"})
	if ex.code != 1 || !strings.HasSuffix(ex.out, "\n") || ex.err != "" {
		t.Fatalf("deny: %+v", ex)
	}
	ex = evalCheck(checkOpts{url: "http://127.0.0.1/", jsonOut: true})
	if ex.code != 1 || !strings.HasPrefix(ex.out, "{") {
		t.Fatalf("json: %+v", ex)
	}
	ex = evalCheck(checkOpts{url: "https://api.anthropic.com/", cfgPath: "/nonexistent.yaml"})
	if ex.code != 2 || !strings.HasPrefix(ex.err, "denyout-cli check: config: ") {
		t.Fatalf("cfg: %+v", ex)
	}
}

func TestParseInitArgs(t *testing.T) {
	o, ex := parseInitArgs([]string{"--x", "a.yaml", "b.yaml"})
	if ex != nil || o.path != "b.yaml" {
		t.Fatalf("%+v %v", o, ex)
	}
	o, _ = parseInitArgs(nil)
	if o.path != "denyout.yaml" {
		t.Fatal(o.path)
	}
	_, ex = parseInitArgs([]string{"-h"})
	wantExit(t, ex, 0, "Usage: denyout-cli init [path]\n", "")
}

func TestParseRunArgs(t *testing.T) {
	env := func(k string) string {
		if k == "DENYOUT_NOTIFY" {
			return "0"
		}
		return ""
	}
	_, ex0 := parseRunArgs([]string{"--config=x"}, noEnv)
	wantExit(t, ex0, 2, "", "denyout-cli run: unknown flag \"--config=x\" (command must follow --)\n")
	o, ex := parseRunArgs([]string{"-c", "c.yaml", "--profile=p", "--tls-mode", "passthrough", "--sandbox=srt", "--", "a", "-b"}, noEnv)
	want := runOpts{cfgPath: "c.yaml", profileID: "p", tlsMode: "passthrough", sandbox: "srt", notify: true, command: []string{"a", "-b"}}
	if ex != nil || !reflect.DeepEqual(o, want) {
		t.Fatalf("%+v %v", o, ex)
	}
	o, _ = parseRunArgs([]string{"--"}, env)
	if o.notify || o.tlsMode != string(proxy.TLSIntercept) {
		t.Fatalf("env default: %+v", o)
	}
	o, _ = parseRunArgs([]string{"--notify"}, env)
	if !o.notify {
		t.Fatal("--notify overrides env")
	}
	o, _ = parseRunArgs([]string{"--no-notify"}, noEnv)
	if o.notify {
		t.Fatal("--no-notify")
	}
}

func TestParseServeArgs(t *testing.T) {
	o, ex := parseServeArgs([]string{"-c", "p", "--listen=:1", "--metrics-listen", "m", "--health-listen=h", "--tls-mode", "passthrough", "--ca-dir=d"})
	want := serve.Options{ConfigPath: "p", Listen: ":1", MetricsListen: "m", HealthListen: "h", TLSMode: proxy.TLSPassthrough, CADir: "d", Version: version}
	if ex != nil || o != want {
		t.Fatalf("%+v %v", o, ex)
	}
	o, _ = parseServeArgs([]string{"-c", "p"})
	if o.TLSMode != "" {
		t.Fatalf("default tls mode must stay empty: %q", o.TLSMode)
	}
	_, ex = parseServeArgs([]string{"-c", "p", "--tls-mode=x"})
	wantExit(t, ex, 2, "", "denyout-cli serve: invalid tls-mode \"x\"\n")
	_, ex = parseServeArgs(nil)
	wantExit(t, ex, 2, "", "denyout-cli serve: --config is required\n")
}

func TestParseGUIArgs(t *testing.T) {
	o, ex := parseGUIArgs([]string{"--no-open", "-c", "c", "--tls-mode=passthrough", "--listen", "localhost:5"})
	if ex != nil || o.OpenBrowser || o.ConfigPath != "c" || o.TLSMode != proxy.TLSPassthrough || o.Listen != "localhost:5" || o.Version != version {
		t.Fatalf("%+v %v", o, ex)
	}
	o, _ = parseGUIArgs(nil)
	if !o.OpenBrowser || o.Listen != "127.0.0.1:0" || o.TLSMode != proxy.TLSIntercept {
		t.Fatalf("defaults: %+v", o)
	}
	_, ex = parseGUIArgs([]string{"--listen=1.2.3.4:5"})
	wantExit(t, ex, 2, "", "denyout-cli gui: --listen must be 127.0.0.1 or localhost (desktop UI is local-only)\n")
}

func TestParseDesktopArgs(t *testing.T) {
	o, ex := parseDesktopArgs([]string{"--setup", "--no-tray", "--no-open", "-c", "c"})
	if ex != nil || !o.forceSetup || !o.noTray || !o.noOpen || o.webUI || o.cfgPath != "c" || o.listen != "127.0.0.1:0" {
		t.Fatalf("%+v %v", o, ex)
	}
	o, _ = parseDesktopArgs([]string{"--listen=localhost:9"})
	if !o.webUI || o.listen != "localhost:9" {
		t.Fatalf("--listen implies web UI: %+v", o)
	}
	// --install skips the listen check (it never serves a UI)
	o, ex = parseDesktopArgs([]string{"--install", "--listen=0.0.0.0:1"})
	if ex != nil || !o.install {
		t.Fatalf("%+v %v", o, ex)
	}
	_, ex = parseDesktopArgs([]string{"--web-ui", "--listen", "1.1.1.1:1"})
	wantExit(t, ex, 2, "", "denyout-cli desktop: --listen must be 127.0.0.1 or localhost\n")
}

func TestParseAuditTail(t *testing.T) {
	o, ex := parseAuditTail([]string{"-n", "5", "--denials", "--path", "p"})
	if ex != nil || o != (auditOpts{limit: 5, denialsOnly: true, path: "p"}) {
		t.Fatalf("%+v %v", o, ex)
	}
	o, _ = parseAuditTail(nil)
	if o.limit != 50 {
		t.Fatal(o.limit)
	}
	_, ex = parseAuditTail([]string{"-n", "-2"})
	wantExit(t, ex, 2, "", "denyout-cli audit tail: invalid -n \"-2\"\n")
}

func TestParseLabTestArgs(t *testing.T) {
	o, ex := parseLabTestArgs([]string{"--db=a", "--suite", "s", "--corpus-jsonl", "x", "--corpus-jsonl=y", "--quiet", "--metrics"})
	want := labTestOpts{dbPath: "a", suite: "s", quiet: true, metrics: true, corpus: []string{"x", "y"}}
	if ex != nil || !reflect.DeepEqual(o, want) {
		t.Fatalf("%+v %v", o, ex)
	}
	o, _ = parseLabTestArgs([]string{"--corpus-jsonl=x"})
	if o.dbPath != labDefaultCorpusDB {
		t.Fatalf("corpus db default: %q", o.dbPath)
	}
	o, _ = parseLabTestArgs([]string{"--corpus-jsonl=x", "--db", labDefaultDB})
	if o.dbPath != labDefaultCorpusDB {
		t.Fatalf("explicit default path also swapped (legacy): %q", o.dbPath)
	}
	o, _ = parseLabTestArgs(nil)
	if o.dbPath != labDefaultDB {
		t.Fatal(o.dbPath)
	}
}

func TestLabExitCodeAndReport(t *testing.T) {
	if labExitCode(labTestOpts{}, 0) != 0 || labExitCode(labTestOpts{}, 2) != 1 || labExitCode(labTestOpts{corpus: []string{"x"}}, 2) != 0 {
		t.Fatal("labExitCode")
	}
}

func TestParseUninstallArgs(t *testing.T) {
	o, ex := parseUninstallArgs([]string{"--keep-config", "-y"})
	if ex != nil || !o.KeepConfig || !o.Yes {
		t.Fatalf("%+v %v", o, ex)
	}
	o, _ = parseUninstallArgs([]string{"--yes"})
	if !o.Yes || o.KeepConfig {
		t.Fatalf("%+v", o)
	}
}

func TestParseHostctlSpecArgs(t *testing.T) {
	o, ex := parseHostctlSpecArgs([]string{"--port", "9", "--ca=/c", "--uid", "7", "--no-elevate", "--allow-quic", "--tun", "--fail-policy=open"})
	want := hostctlSpecOpts{port: 9, ca: "/c", uid: 7, noElevate: true, allowQUIC: true, tunPreview: true, failPolicy: "open"}
	if ex != nil || o != want {
		t.Fatalf("%+v %v", o, ex)
	}
	if o.spec().ProxyPort != 9 || o.spec().CACert != "/c" || o.spec().UID != 7 || !o.spec().AllowQUIC {
		t.Fatalf("spec: %+v", o.spec())
	}
	o, ex = parseHostctlSpecArgs([]string{"--port=abc", "--ca"})
	if ex != nil || o.port != 0 || o.ca != "" {
		t.Fatalf("lenient: %+v %v", o, ex)
	}
	_, ex = parseHostctlSpecArgs([]string{"stray"})
	wantExit(t, ex, 2, "", "denyout-cli hostctl: unknown flag \"stray\"\n")
}

func TestParseProxydArgs(t *testing.T) {
	o, ex := parseProxydArgs([]string{"--port=1", "--ca-dir", "/d", "--ask", "--allow-base=b", "--control-url", "c"})
	want := proxydOpts{port: 1, caDir: "/d", ask: true, allowBase: "b", controlURL: "c"}
	if ex != nil || o != want {
		t.Fatalf("%+v %v", o, ex)
	}
}

func TestParseProfileHelpers(t *testing.T) {
	name, cmd, ex := parseProfileCreate([]string{"--name=a b", "--", "x", "--y"})
	if ex != nil || name != "a b" || !reflect.DeepEqual(cmd, []string{"x", "--y"}) {
		t.Fatalf("%q %v %v", name, cmd, ex)
	}
	name, _, ex = parseProfileCreate([]string{"--name", "n", "--", "x"})
	if ex != nil || name != "n" {
		t.Fatalf("%q %v", name, ex)
	}
	_, _, ex = parseProfileCreate([]string{"--name"})
	wantExit(t, ex, 2, "", "denyout-cli profile create: need --name and -- <command>\n")
	force, pos := parseProfileImport([]string{"a", "--force", "b"})
	if !force || !reflect.DeepEqual(pos, []string{"a", "b"}) {
		t.Fatalf("%v %v", force, pos)
	}
	id, ex := profileID([]string{"show", "p1"})
	if id != "p1" || ex != nil {
		t.Fatal(id, ex)
	}
}

// --- run: side effects behind runDeps -------------------------------------

type runFake struct {
	deps    runDeps
	chdirTo string
}

func newRunFake(env map[string]string, prof profileSpec, perr error, code int, eerr error) (*runFake, *[]interface{}) {
	f := &runFake{}
	var execs []interface{}
	f.deps = runDeps{
		getenv:      func(k string) string { return env[k] },
		loadProfile: func(string) (profileSpec, error) { return prof, perr },
		chdir:       func(d string) error { f.chdirTo = d; return nil },
		exec: func(o runOptionsT) (int, error) {
			execs = append(execs, o)
			return code, eerr
		},
	}
	return f, &execs
}

func TestExecRun(t *testing.T) {
	f, execs := newRunFake(map[string]string{"DENYOUT_DESKTOP_NOTIFY": "1"}, profileSpec{}, nil, 7, nil)
	ex := execRun(runOpts{command: []string{"a"}, tlsMode: "intercept"}, f.deps)
	if ex.code != 7 || ex.err != "" || len(*execs) != 1 {
		t.Fatalf("%+v", ex)
	}
	if o := (*execs)[0].(runOptionsT); !o.Notify || o.Command[0] != "a" || o.TLSMode != proxy.TLSIntercept {
		t.Fatalf("%+v", o)
	}
	// error with code 0 maps to 2, with code kept otherwise
	f, _ = newRunFake(nil, profileSpec{}, nil, 0, errors.New("boom"))
	ex = execRun(runOpts{command: []string{"a"}, tlsMode: "passthrough"}, f.deps)
	if ex.code != 2 || ex.err != "denyout-cli run: boom\n" {
		t.Fatalf("%+v", ex)
	}
	f, _ = newRunFake(nil, profileSpec{}, nil, 9, errors.New("boom"))
	if ex = execRun(runOpts{command: []string{"a"}, tlsMode: "passthrough"}, f.deps); ex.code != 9 {
		t.Fatalf("%+v", ex)
	}
	// validation
	ex = execRun(runOpts{tlsMode: "intercept"}, f.deps)
	wantExit(t, ex, 2, "", "denyout-cli run: missing -- <command> (or --profile with a command)\n")
	ex = execRun(runOpts{command: []string{"a"}, tlsMode: "zzz"}, f.deps)
	wantExit(t, ex, 2, "", "denyout-cli run: invalid tls-mode \"zzz\"\n")
}

func TestExecRunProfile(t *testing.T) {
	prof := profileSpec{configPath: "/tmp/c.yaml", command: []string{"agent", "go"}, sandbox: "srt", requireIsolation: true, workDir: "/w"}
	f, execs := newRunFake(nil, prof, nil, 0, nil)
	ex := execRun(runOpts{profileID: "p", tlsMode: "intercept"}, f.deps)
	if ex.code != 0 || f.chdirTo != "/w" {
		t.Fatalf("%+v chdir=%q", ex, f.chdirTo)
	}
	o := (*execs)[0].(runOptionsT)
	if o.ConfigPath != "/tmp/c.yaml" || o.Sandbox != "srt" || !o.RequireSandbox || !reflect.DeepEqual(o.Command, []string{"agent", "go"}) {
		t.Fatalf("%+v", o)
	}
	// explicit command and sandbox win over the profile's
	f, execs = newRunFake(nil, prof, nil, 0, nil)
	execRun(runOpts{profileID: "p", tlsMode: "intercept", sandbox: "x", command: []string{"mine"}}, f.deps)
	o = (*execs)[0].(runOptionsT)
	if o.Sandbox != "x" || o.Command[0] != "mine" {
		t.Fatalf("%+v", o)
	}
	// load failure
	f, _ = newRunFake(nil, profileSpec{}, errors.New("profile: gone"), 0, nil)
	wantExit(t, execRun(runOpts{profileID: "p"}, f.deps), 2, "", "denyout-cli run: profile: gone\n")
	// chdir failure
	f, _ = newRunFake(nil, prof, nil, 0, nil)
	f.deps.chdir = func(string) error { return errors.New("nope") }
	wantExit(t, execRun(runOpts{profileID: "p"}, f.deps), 2, "", "denyout-cli run: workdir: nope\n")
}

// --- long-running commands with injected runners --------------------------

func TestCmdServeGuiDesktopRunners(t *testing.T) {
	oldS, oldG, oldDI, oldDR, oldN := serveRun, guiRun, desktopInstall, desktopRun, notifyContext
	t.Cleanup(func() { serveRun, guiRun, desktopInstall, desktopRun, notifyContext = oldS, oldG, oldDI, oldDR, oldN })
	notifyContext = func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) }

	var gotServe serve.Options
	serveRun = func(_ context.Context, o serve.Options) error { gotServe = o; return nil }
	if code, _, _ := capture(t, func() int { return runMain([]string{"serve", "-c", "p"}) }); code != 0 || gotServe.ConfigPath != "p" {
		t.Fatalf("serve: %d %+v", code, gotServe)
	}
	serveRun = func(context.Context, serve.Options) error { return errors.New("down") }
	if code, _, e := capture(t, func() int { return runMain([]string{"serve", "-c", "p"}) }); code != 2 || e != "denyout-cli serve: down\n" {
		t.Fatalf("serve err: %d %q", code, e)
	}

	guiRun = func(context.Context, guiOptionsT) error { return nil }
	if code, _, _ := capture(t, func() int { return runMain([]string{"gui", "--no-open"}) }); code != 0 {
		t.Fatalf("gui: %d", code)
	}
	guiRun = func(context.Context, guiOptionsT) error { return errors.New("down") }
	if code, _, e := capture(t, func() int { return runMain([]string{"gui"}) }); code != 2 || e != "denyout-cli gui: down\n" {
		t.Fatalf("gui err: %d %q", code, e)
	}

	var inst desktop.Options
	desktopInstall = func(o desktop.Options) error { inst = o; return nil }
	if code, _, _ := capture(t, func() int { return runMain([]string{"desktop", "--install", "-c", "cfg"}) }); code != 0 || inst.ConfigPath != "cfg" || inst.Version != version {
		t.Fatalf("install: %d %+v", code, inst)
	}
	desktopInstall = func(desktop.Options) error { return errors.New("x") }
	if code, _, e := capture(t, func() int { return runMain([]string{"desktop", "--install"}) }); code != 2 || e != "denyout-cli desktop --install: x\n" {
		t.Fatalf("install err: %d %q", code, e)
	}
	var ran desktop.Options
	desktopRun = func(_ context.Context, o desktop.Options) error { ran = o; return nil }
	if code, _, _ := capture(t, func() int { return runMain([]string{"desktop", "--setup", "--no-tray", "--web-ui"}) }); code != 0 || !ran.ForceSetup || !ran.NoTray || !ran.WebUI || ran.Listen != "127.0.0.1:0" {
		t.Fatalf("desktop: %d %+v", code, ran)
	}
	desktopRun = func(context.Context, desktop.Options) error { return errors.New("y") }
	if code, _, e := capture(t, func() int { return runMain([]string{"desktop"}) }); code != 2 || e != "denyout-cli desktop: y\n" {
		t.Fatalf("desktop err: %d %q", code, e)
	}
}

func TestCmdUninstallRunner(t *testing.T) {
	old := uninstallRun
	t.Cleanup(func() { uninstallRun = old })
	var got desktop.UninstallOptions
	uninstallRun = func(o desktop.UninstallOptions) error { got = o; return nil }
	if code, _, _ := capture(t, func() int { return runMain([]string{"uninstall", "--keep-config", "--yes"}) }); code != 0 || !got.KeepConfig || !got.Yes {
		t.Fatalf("%d %+v", code, got)
	}
	uninstallRun = func(desktop.UninstallOptions) error { return errors.New("bad") }
	if code, _, e := capture(t, func() int { return runMain([]string{"uninstall"}) }); code != 1 || e != "denyout-cli uninstall: bad\n" {
		t.Fatalf("%d %q", code, e)
	}
}

func TestProfileRunDispatch(t *testing.T) {
	old := profileRunFn
	t.Cleanup(func() { profileRunFn = old })
	var id string
	profileRunFn = func(i string) int { id = i; return 5 }
	if code, _, _ := capture(t, func() int { return runMain([]string{"profile", "run", "abc"}) }); code != 5 || id != "abc" {
		t.Fatalf("%d %q", code, id)
	}
}

func TestRunAuditTailFake(t *testing.T) {
	oldT, oldP := auditTailEvents, auditLogPath
	t.Cleanup(func() { auditTailEvents, auditLogPath = oldT, oldP })
	auditLogPath = func() string { return "/default/audit.jsonl" }
	var gotPath string
	auditTailEvents = func(p string, n int, d bool) ([]auditEventT, error) {
		gotPath = p
		return nil, nil
	}
	ex := runAuditTail(auditOpts{limit: 1})
	if gotPath != "/default/audit.jsonl" || ex.code != 0 || ex.err != "denyout-cli audit tail: no events\n" {
		t.Fatalf("%q %+v", gotPath, ex)
	}
	auditTailEvents = func(string, int, bool) ([]auditEventT, error) { return nil, errors.New("io") }
	wantExit(t, runAuditTail(auditOpts{path: "p"}), 1, "", "denyout-cli audit tail: io\n")
}
