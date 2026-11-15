package desktop_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/desktop"
)

func TestInstallStateShapeIsOffPending(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	st := desktop.State{
		SetupDone:         false,
		ProtectionOn:      false,
		ComputerEnabled:   false,
		Scope:             desktop.ScopeOff,
		PolicyProfile:     desktop.PolicyProfileBrowse,
		Notify:            true,
		Autostart:         false,
		AutostartAsked:    false,
		ComputerAvailable: true,
		UXv2Migrated:      true,
	}
	if err := desktop.SaveState(st); err != nil {
		t.Fatal(err)
	}
	got := desktop.LoadState()
	if got.SetupDone || got.ProtectionOn || got.ComputerEnabled {
		t.Fatalf("expected pending Off setup, got setup=%v on=%v computer=%v",
			got.SetupDone, got.ProtectionOn, got.ComputerEnabled)
	}
	if got.Scope != desktop.ScopeOff {
		t.Fatalf("scope=%q", got.Scope)
	}
}

func TestProtectConfirmTextMentionsPassword(t *testing.T) {
	title, body := desktop.ProtectConfirmText(false)
	if title == "" || body == "" {
		t.Fatal("empty confirm")
	}
	if !strings.Contains(strings.ToLower(body), "password") {
		t.Fatalf("expected password in body: %s", body)
	}
	_, bodyOK := desktop.ProtectConfirmText(true)
	low := strings.ToLower(bodyOK)
	if !strings.Contains(low, "helper") && !strings.Contains(low, "password") {
		t.Fatalf("helper path body unexpected: %s", bodyOK)
	}
}
