package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/audit"
)

func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	return dir
}

func TestDoctorRedactsAndNeverMutates(t *testing.T) {
	dir := isolate(t)

	tok := "ghp_" + strings.Repeat("a1B2", 9)
	ev := audit.Event{
		EventID: "e1", TS: "2026-01-01T00:00:00Z", Verdict: "deny",
		Reasons: []string{"secret_in_url"}, Detectors: []string{"github_token"},
		Network: audit.Network{DestHost: "evil.example", DestPort: 443},
		HTTP:    &audit.HTTPInfo{Method: "GET", Path: "/p", QueryRedacted: "x=" + tok},
	}
	line, _ := json.Marshal(ev)
	ap := audit.DefaultDesktopPath()
	if err := os.MkdirAll(filepath.Dir(ap), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ap, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{{}, {"--json"}} {
		var out, errb bytes.Buffer
		if code := cmdDoctor(args, &out, &errb); code != 0 {
			t.Fatalf("code %d: %s", code, errb.String())
		}
		if strings.Contains(out.String(), tok) {
			t.Fatalf("doctor leaked a secret:\n%s", out.String())
		}
		if !strings.Contains(out.String(), "evil.example") {
			t.Fatalf("denial missing:\n%s", out.String())
		}
	}
	// No CA directory may appear: doctor only reads.
	if _, err := os.Stat(filepath.Join(dir, "config", "denyout", "ca")); err == nil {
		t.Fatal("doctor must not create the CA")
	}
}

func TestDoctorArgs(t *testing.T) {
	isolate(t)
	var out, errb bytes.Buffer
	if code := cmdDoctor([]string{"--bogus"}, &out, &errb); code != 2 {
		t.Fatalf("bogus: %d", code)
	}
	if code := cmdDoctor([]string{"-n"}, &out, &errb); code != 2 {
		t.Fatalf("-n: %d", code)
	}
	if code := cmdDoctor([]string{"-h"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "Usage") {
		t.Fatal("help")
	}
	// --strict fails when Protect is expected but there is no CA.
	if code := cmdDoctor([]string{"--strict", "--protect-on"}, &out, &errb); code != 1 {
		t.Fatalf("strict: %d", code)
	}
}
