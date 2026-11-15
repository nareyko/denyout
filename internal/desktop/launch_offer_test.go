package desktop

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUIReadyRestoreOffersProtectWhenOff(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	var opened string
	a := &App{state: DefaultState(), status: "Off", wraps: map[string]*wrapProc{}}
	a.state.SetupDone = true
	a.state.ProtectionOn = false
	a.opts.OpenUI = func(route string) { opened = route }
	a.UIReadyRestore()
	if opened != "enable-protect" {
		t.Fatalf("opened=%q want enable-protect", opened)
	}
	assertEventType(t, EventsLogPath(), "launch_offer_protect")
}

func TestUIReadyRestoreSkipsForeverPause(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	var opened string
	a := &App{state: DefaultState(), status: "Off", wraps: map[string]*wrapProc{}}
	a.state.SetupDone = true
	a.state.ProtectionOn = true
	a.state.ComputerEnabled = true
	a.state.ProtectPauseLast = "forever"
	a.opts.OpenUI = func(route string) { opened = route }
	a.UIReadyRestore()
	if opened != "home" {
		t.Fatalf("opened=%q want home", opened)
	}
	if a.proxyd != nil {
		t.Fatal("paused forever must not restore Protect")
	}
	assertEventType(t, EventsLogPath(), "restore_skipped")
}

func TestUIReadyRestoreSkipsSetup(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	var opened string
	a := &App{state: DefaultState(), status: "Off", wraps: map[string]*wrapProc{}}
	a.state.SetupDone = false
	a.opts.OpenUI = func(route string) { opened = route }
	a.UIReadyRestore()
	if opened != "" {
		t.Fatalf("opened=%q want empty (mode-choice owns first-run)", opened)
	}
	assertEventType(t, EventsLogPath(), "restore_skipped")
}

func TestLogBlockWritesJSONL(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	LogBlock("deny", map[string]any{"host": "evil.example", "reasons": []string{"threat_list"}})
	assertEventType(t, BlocksLogPath(), "deny")
	b, err := os.ReadFile(DesktopLogPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "block=deny") {
		t.Fatalf("desktop.log missing block mirror: %s", b)
	}
}

func assertEventType(t *testing.T, path, wantType string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	found := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		if rec["type"] == wantType {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no %q in %s", wantType, path)
	}
}
