//go:build linux

package desktop

import (
	"errors"
	"testing"
)

func TestParseLockedHint(t *testing.T) {
	cases := map[string][2]bool{
		"yes\n": {true, true}, "TRUE": {true, true}, "1": {true, true},
		"no": {false, true}, "false\n": {false, true}, "0": {false, true},
		"": {false, false}, "maybe": {false, false},
	}
	for in, want := range cases {
		if l, ok := parseLockedHint(in); l != want[0] || ok != want[1] {
			t.Errorf("%q: %v %v", in, l, ok)
		}
	}
}

func TestParseScreenSaverActive(t *testing.T) {
	cases := map[string][2]bool{
		"   boolean true": {true, true}, "boolean 1": {true, true},
		"   boolean false": {false, true}, "boolean 0": {false, true},
		"": {false, false}, "junk": {false, false},
	}
	for in, want := range cases {
		if l, ok := parseScreenSaverActive(in); l != want[0] || ok != want[1] {
			t.Errorf("%q: %v %v", in, l, ok)
		}
	}
}

func TestProbeScreenLocked(t *testing.T) {
	old := probeCmd
	t.Cleanup(func() { probeCmd = old })

	t.Setenv("XDG_SESSION_ID", "7")
	probeCmd = func(name string, args ...string) ([]byte, error) {
		if name == "loginctl" {
			return []byte("yes\n"), nil
		}
		return nil, errors.New("unexpected")
	}
	if l, ok := probeScreenLocked(); !l || !ok {
		t.Fatal("loginctl locked")
	}

	// loginctl unknown -> dbus first path
	probeCmd = func(name string, args ...string) ([]byte, error) {
		if name == "loginctl" {
			return nil, errors.New("no")
		}
		return []byte("boolean false"), nil
	}
	if l, ok := probeScreenLocked(); l || !ok {
		t.Fatal("dbus unlocked")
	}

	// first path errors, gnome path answers
	t.Setenv("XDG_SESSION_ID", "")
	probeCmd = func(name string, args ...string) ([]byte, error) {
		if args[len(args)-2] == "/org/gnome/ScreenSaver" {
			return []byte("boolean true"), nil
		}
		return nil, errors.New("no")
	}
	if l, ok := probeScreenLocked(); !l || !ok {
		t.Fatal("gnome path")
	}

	// garbage then nothing
	probeCmd = func(name string, args ...string) ([]byte, error) { return []byte("junk"), nil }
	if _, ok := probeScreenLocked(); ok {
		t.Fatal("unknown expected")
	}
	probeCmd = func(name string, args ...string) ([]byte, error) { return nil, errors.New("x") }
	if _, ok := probeScreenLocked(); ok {
		t.Fatal("all fail")
	}
}
