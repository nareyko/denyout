package desktop

import (
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/audit"
)

type fakeDialog struct {
	tools    map[string]bool
	out      string
	err      error
	gotName  string
	gotArgs  []string
	combined bool
	calls    int
}

func installFakeDialog(t *testing.T, goos string, tools ...string) *fakeDialog {
	t.Helper()
	f := &fakeDialog{tools: map[string]bool{}}
	for _, n := range tools {
		f.tools[n] = true
	}
	og, ol, oe := dialogGOOS, dialogLookPath, dialogExec
	t.Cleanup(func() { dialogGOOS, dialogLookPath, dialogExec = og, ol, oe })
	dialogGOOS = goos
	dialogLookPath = func(n string) (string, error) {
		if f.tools[n] {
			return "/usr/bin/" + n, nil
		}
		return "", errors.New("not found")
	}
	dialogExec = func(combined bool, name string, args ...string) ([]byte, error) {
		f.calls++
		f.gotName, f.gotArgs, f.combined = name, args, combined
		return []byte(f.out), f.err
	}
	return f
}

func exitErr(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command("sh", "-c", "exit "+string(rune('0'+code))).Run()
	if err == nil {
		t.Skip("cannot produce exit error")
	}
	return err
}

func TestExitCodeOf(t *testing.T) {
	if exitCodeOf(nil) != 0 || exitCodeOf(errors.New("x")) != 2 {
		t.Fatal("bad")
	}
	if got := exitCodeOf(exitErr(t, 1)); got != 1 {
		t.Fatal(got)
	}
}

func TestZenityAskArgs(t *testing.T) {
	want := []string{"--question", "--title=DenyOut", "--text=hi", "--ok-label=Allow once",
		"--cancel-label=Keep blocked", "--extra-button=Always allow", "--width=480", "--default-cancel"}
	if got := zenityAskArgs("hi"); !reflect.DeepEqual(got, want) {
		t.Fatalf("%q", got)
	}
}

func TestParseAsk(t *testing.T) {
	if parseZenityAsk([]byte("Always allow\n"), errors.New("x")) != "always" ||
		parseZenityAsk(nil, nil) != "once" || parseZenityAsk(nil, errors.New("x")) != "deny" {
		t.Fatal("zenity")
	}
	if parseKdialogAsk(0) != "once" || parseKdialogAsk(1) != "always" || parseKdialogAsk(2) != "deny" {
		t.Fatal("kdialog")
	}
	if parseOsascriptAsk([]byte("Always allow\n")) != "always" || parseOsascriptAsk([]byte("Allow once")) != "once" ||
		parseOsascriptAsk([]byte("Keep blocked")) != "deny" {
		t.Fatal("osascript")
	}
	if parseAskPowershell([]byte(" Once\r\n")) != "once" || parseAskPowershell([]byte("always")) != "always" ||
		parseAskPowershell([]byte("deny")) != "deny" || parseAskPowershell([]byte("???")) != "deny" {
		t.Fatal("powershell")
	}
}

func TestScriptBuilders(t *testing.T) {
	s := osascriptAskScript(`say "x"`)
	if !strings.Contains(s, `display dialog "say \"x\""`) || !strings.Contains(s, `buttons {"Keep blocked","Allow once","Always allow"}`) {
		t.Fatal(s)
	}
	p := powershellAskScript("hi")
	if !strings.Contains(p, `Show("hi", 'DenyOut - new site', 'YesNoCancel', 'Question')`) || !strings.Contains(p, "'once'") {
		t.Fatal(p)
	}
	if a := kdialogAskArgs("t"); a[0] != "--yesnocancel" || a[1] != "t" || a[len(a)-1] != "DenyOut" {
		t.Fatal(a)
	}
}

func TestRunAskDialogPlatforms(t *testing.T) {
	f := installFakeDialog(t, "linux", "zenity")
	f.out = "Always allow"
	f.err = errors.New("exit 1")
	if got := runAskDialog("q"); got != "always" || f.gotName != "/usr/bin/zenity" || !f.combined {
		t.Fatalf("%s %+v", got, f)
	}
	f = installFakeDialog(t, "linux", "kdialog")
	f.err = exitErr(t, 1)
	if got := runAskDialog("q"); got != "always" || f.gotArgs[0] != "--yesnocancel" {
		t.Fatalf("%s %+v", got, f)
	}
	f.err = nil
	if runAskDialog("q") != "once" {
		t.Fatal("kdialog once")
	}
	installFakeDialog(t, "linux")
	if runAskDialog("q") != "deny" {
		t.Fatal("no toolkit")
	}
	f = installFakeDialog(t, "darwin")
	f.out = "Allow once"
	if runAskDialog("q") != "once" || f.gotName != "osascript" || f.gotArgs[0] != "-e" {
		t.Fatalf("%+v", f)
	}
	f.err = errors.New("x")
	if runAskDialog("q") != "deny" {
		t.Fatal("darwin err")
	}
	f = installFakeDialog(t, "windows")
	f.out = "always\r\n"
	if runAskDialog("q") != "always" || f.gotName != "powershell" || f.gotArgs[0] != "-NoProfile" {
		t.Fatalf("%+v", f)
	}
	f.err = errors.New("x")
	if runAskDialog("q") != "deny" {
		t.Fatal("windows err")
	}
	installFakeDialog(t, "plan9")
	if runAskDialog("q") != "deny" {
		t.Fatal("other os")
	}
}

func denialEvents() []audit.Event {
	mk := func(host, ts string, reasons ...string) audit.Event {
		e := audit.Event{TS: ts, Reasons: reasons}
		e.Network.DestHost = host
		return e
	}
	return []audit.Event{
		mk("old.example", "2026-01-02T03:04:05Z", "not_in_allowlist"),
		mk("", "2026-01-02T03:04:06Z", "x"),
		mk("new.example", "", "not_in_allowlist"),
	}
}

func TestZenityDenialsRows(t *testing.T) {
	r := zenityDenialsRows(denialEvents())
	if len(r.byIdx) != 2 || r.byIdx["1"].Network.DestHost != "new.example" || r.byIdx["2"].Network.DestHost != "old.example" {
		t.Fatalf("%+v", r.byIdx)
	}
	base := zenityDenialsBaseArgs()
	if !reflect.DeepEqual(r.args[:len(base)], base) || len(r.args) != len(base)+10 {
		t.Fatalf("%q", r.args)
	}
	cells := r.args[len(base):]
	if cells[0] != "1" || cells[1] != "-" || cells[2] != "new.example" || cells[3] != "https://new.example/" {
		t.Fatalf("%q", cells)
	}
	if cells[6] != "03:04:05" {
		t.Fatalf("%q", cells)
	}
	if r.hostReason["old.example"] == "" {
		t.Fatalf("%v", r.hostReason)
	}
	_, _, long := zenityDenialCells(audit.Event{Reasons: []string{strings.Repeat("zzzz", 30)}}, "h")
	if len(long) > 72 {
		t.Fatal(long)
	}
}

func TestParseZenityDenials(t *testing.T) {
	r := zenityDenialsRows(denialEvents())
	cases := []struct {
		out    string
		err    error
		action string
		host   string
	}{
		{"Refresh", nil, "refresh", ""},
		{"1", nil, "details", "new.example"},
		{"2\nAlways allow", errors.New("x"), "always", "old.example"},
		{"Undo\n2", errors.New("x"), "undo", "old.example"},
		{"9", nil, "close", ""},
		{"", errors.New("cancel"), "close", ""},
		{"1", errors.New("cancel"), "close", ""},
	}
	for _, c := range cases {
		h, _, act, _ := parseZenityDenials([]byte(c.out), c.err, r)
		if h != c.host || act != c.action {
			t.Errorf("%q: got %q %q want %q %q", c.out, h, act, c.host, c.action)
		}
	}
}

func TestDenialsChooserZenityRun(t *testing.T) {
	f := installFakeDialog(t, "linux", "zenity")
	f.out = "1"
	h, _, act, ev := nativeDenialsChooserV2(denialEvents())
	if h != "new.example" || act != "details" || ev == nil || !f.combined || f.gotArgs[0] != "--list" {
		t.Fatalf("%s %s %+v", h, act, f)
	}
	f.calls = 0
	if _, _, act, _ := nativeDenialsChooserV2(nil); act != "close" || f.calls != 0 {
		t.Fatal("empty list must not run zenity")
	}
	h2, act2, _ := nativeDenialsChooser(denialEvents())
	if h2 != "new.example" || act2 != "details" {
		t.Fatal(h2, act2)
	}
	installFakeDialog(t, "linux")
	if _, _, act, _ := nativeDenialsChooserZenityV2(denialEvents()); act != "close" {
		t.Fatal("no zenity")
	}
}

func TestDenialsChooserKdialog(t *testing.T) {
	f := installFakeDialog(t, "linux", "kdialog")
	f.out = "old.example\n"
	h, reason, act, ev := nativeDenialsChooserV2(denialEvents())
	if h != "old.example" || act != "details" || ev == nil || reason != "" || f.gotArgs[0] != "--menu" {
		t.Fatalf("%s %s %+v", h, act, f)
	}
	items, byHost := kdialogDenialItems(denialEvents())
	if len(items) != 4 || items[0] != "new.example" || len(byHost) != 2 {
		t.Fatal(items)
	}
	f.err = errors.New("cancel")
	if _, act, _ := nativeDenialsChooser(denialEvents()); act != "close" {
		t.Fatal(act)
	}
	if _, act, _ := nativeDenialsChooser(nil); act != "close" {
		t.Fatal(act)
	}
}

func TestDenialsChooserNoToolkit(t *testing.T) {
	installFakeDialog(t, "linux")
	if _, act, _ := nativeDenialsChooser(denialEvents()); act != "close" {
		t.Fatal(act)
	}
	installFakeDialog(t, "plan9")
	if _, act, _ := nativeDenialsChooser(denialEvents()); act != "close" {
		t.Fatal(act)
	}
}

func TestDenialsChooserDarwin(t *testing.T) {
	f := installFakeDialog(t, "darwin")
	ev := denialEvents()
	ev[2].Reasons = []string{`quote"d`}
	r := darwinDenialLines(ev)
	if len(r.lines) != 2 || strings.Contains(r.lines[0], `"`) {
		t.Fatal(r.lines)
	}
	script := darwinDenialsScript(r.lines)
	if !strings.HasPrefix(script, `set hostList to {"`) || !strings.Contains(script, `","`) {
		t.Fatal(script)
	}
	f.out = r.lines[1] + "\n"
	h, act, e := nativeDenialsChooser(ev)
	if h != "old.example" || act != "details" || e == nil || f.gotName != "osascript" {
		t.Fatalf("%s %s", h, act)
	}
	for _, out := range []string{"CLOSE", "", "unknown row"} {
		f.out = out
		if _, act, _ := nativeDenialsChooser(ev); act != "close" {
			t.Fatal(out)
		}
	}
	f.err = errors.New("x")
	if _, act, _ := nativeDenialsChooser(ev); act != "close" {
		t.Fatal("err")
	}
	f.calls = 0
	if _, act, _ := nativeDenialsChooser(nil); act != "close" || f.calls != 0 {
		t.Fatal("empty")
	}
	if len(darwinDenialLines(manyEvents(40)).lines) != 25 {
		t.Fatal("cap 25")
	}
}

func manyEvents(n int) []audit.Event {
	var out []audit.Event
	for i := 0; i < n; i++ {
		e := audit.Event{}
		e.Network.DestHost = "h" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example"
		out = append(out, e)
	}
	return out
}

func TestDenialsChooserWindows(t *testing.T) {
	f := installFakeDialog(t, "windows")
	msg, host, ev := windowsDenialsMessage(denialEvents())
	if host != "new.example" || ev == nil || !strings.HasPrefix(msg, "Recent denials:\n- new.example\n https://new.example/\n") ||
		!strings.HasSuffix(msg, "Open details for first host new.example?") {
		t.Fatalf("%q", msg)
	}
	if !strings.Contains(windowsDenialsScript(msg), "'DenyOut - What was blocked', 'YesNo', 'Information'") {
		t.Fatal("script")
	}
	f.out = "details\r\n"
	h, act, _ := nativeDenialsChooser(denialEvents())
	if h != "new.example" || act != "details" || f.gotName != "powershell" {
		t.Fatalf("%s %s", h, act)
	}
	f.out = "close"
	if _, act, _ := nativeDenialsChooser(denialEvents()); act != "close" {
		t.Fatal(act)
	}
	f.err = errors.New("x")
	if _, act, _ := nativeDenialsChooser(denialEvents()); act != "close" {
		t.Fatal(act)
	}
	if len(strings.Split(func() string { m, _, _ := windowsDenialsMessage(manyEvents(40)); return m }(), "\n- ")) != 16 {
		t.Fatal("cap 15 rows")
	}
}
