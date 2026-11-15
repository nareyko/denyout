package desktop

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSessionDenyWritesBlocksJSONL(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	a := &App{state: DefaultState(), status: "Off", wraps: map[string]*wrapProc{}, asks: newAskFlight()}
	// Agent + no Ask: avoid browse post-block goroutine racing lastBlockRec.
	a.state.PolicyProfile = PolicyProfileAgent
	a.state.AskMode = false
	a.onSessionDeny("evil.example", []string{"secret_in_url"}, "https://evil.example/x")

	rec := lastBlockOfType(t, BlocksLogPath(), "deny")
	if rec["source"] != "session" {
		t.Fatalf("source=%v want session", rec["source"])
	}
	if rec["host"] != "evil.example" {
		t.Fatalf("host=%v", rec["host"])
	}
	if rec["profile"] != PolicyProfileAgent {
		t.Fatalf("profile=%v", rec["profile"])
	}
}

func TestTimedDenyExpireWritesBlocksJSONL(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}, asks: newAskFlight()}
	a.addTimedDeny("example.com", "secret_in_url", -time.Minute)
	a.sweepTimedRules()
	assertBlockType(t, BlocksLogPath(), "timed_deny_expire")
}

func TestSilentAskAnsweredLogged(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	a := testAppPresence()
	a.setScreenLocked(true)
	_ = a.coalescedAskProfile("new.example", "host_not_allowed", "Agent", "p1")
	rec := lastBlockRec(t, BlocksLogPath())
	if rec["type"] != "ask_answered" {
		t.Fatalf("type=%v", rec["type"])
	}
	if rec["source"] != "away_or_fullscreen" {
		t.Fatalf("source=%v", rec["source"])
	}
	if rec["action"] != AskDeny {
		t.Fatalf("action=%v", rec["action"])
	}
}

func TestRememberKeepWritesBlocksJSONL(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	a := &App{state: DefaultState(), wraps: map[string]*wrapProc{}}
	a.rememberKeep("bad.example", "threat_list")
	assertBlockType(t, BlocksLogPath(), "remember_keep")
}

func assertBlockType(t *testing.T, path, wantType string) {
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

func lastBlockRec(t *testing.T, path string) map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var last string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		last = sc.Text()
	}
	if last == "" {
		t.Fatal("empty blocks.jsonl")
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(last), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func lastBlockOfType(t *testing.T, path, wantType string) map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var last map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		if rec["type"] == wantType {
			last = rec
		}
	}
	if last == nil {
		t.Fatalf("no %q in %s", wantType, path)
	}
	return last
}
