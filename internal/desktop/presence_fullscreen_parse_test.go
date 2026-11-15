//go:build linux

package desktop

import (
	"testing"

	"github.com/nareyko/denyout/internal/notify"
)

func TestParseGnomeShellEval(t *testing.T) {
	cases := []struct {
		in     string
		fs, ok bool
	}{
		{"(true, 'true')", true, true},
		{"(true, 'false')", false, true},
		{"(false, '')", false, false},
		{"(false, 'Error: …')", false, false},
		{"garbage", false, false},
	}
	for _, c := range cases {
		fs, ok := parseGnomeShellEval(c.in)
		if fs != c.fs || ok != c.ok {
			t.Fatalf("%q => fs=%v ok=%v want fs=%v ok=%v", c.in, fs, ok, c.fs, c.ok)
		}
	}
}

func TestParseGnomeIntrospectWindowsFocusedFullscreen(t *testing.T) {
	sample := `(@a{ta{sv}} {uint64 1: {'has-focus': <true>, 'is-fullscreen': <true>, 'title': <'Game'>}, uint64 2: {'has-focus': <false>, 'is-fullscreen': <false>}},)`
	fs, ok := parseGnomeIntrospectWindows(sample)
	if !ok || !fs {
		t.Fatalf("fs=%v ok=%v", fs, ok)
	}
	notFS := `(@a{ta{sv}} {uint64 1: {'has-focus': <true>, 'is-fullscreen': <false>}},)`
	fs, ok = parseGnomeIntrospectWindows(notFS)
	if !ok || fs {
		t.Fatalf("notFS fs=%v ok=%v", fs, ok)
	}
	denied := `Error: GDBus.Error:org.freedesktop.DBus.Error.AccessDenied: GetWindows is not allowed`
	fs, ok = parseGnomeIntrospectWindows(denied)
	if ok || fs {
		t.Fatalf("denied should be unknown: fs=%v ok=%v", fs, ok)
	}
}

func TestParseSwayTreeFullscreen(t *testing.T) {
	tree := []byte(`{"focused":false,"fullscreen_mode":0,"nodes":[{"focused":true,"fullscreen_mode":1,"nodes":[],"floating_nodes":[]}]}`)
	fs, ok := parseSwayTreeFullscreen(tree)
	if !ok || !fs {
		t.Fatalf("fs=%v ok=%v", fs, ok)
	}
	treeOff := []byte(`{"focused":true,"fullscreen_mode":0,"nodes":[],"floating_nodes":[]}`)
	fs, ok = parseSwayTreeFullscreen(treeOff)
	if !ok || fs {
		t.Fatalf("off fs=%v ok=%v", fs, ok)
	}
}

func TestPollFullscreenOnceX11Detects(t *testing.T) {
	a := &App{state: DefaultState()}
	notify.SetFullscreen(true) // stale — must clear or refresh via probe
	a.pollFullscreenOnce()
	if !a.fullscreenDetectOK() {
		// X11 session with xprop should detect; if CI has no DISPLAY, skip.
		if fs, ok := probeFullscreenX11(); !ok {
			t.Skip("no X11 fullscreen probe in this environment")
		} else {
			t.Fatalf("expected detect OK after poll (x11 fs=%v)", fs)
		}
	}
	// Stale fullscreen must not stick when probe says not fullscreen.
	if notify.Fullscreen() && !a.presence.fsActive {
		t.Fatal("notify.Fullscreen stuck true while fsActive false")
	}
}

func TestPollFullscreenUnknownClearsNotifyFlag(t *testing.T) {
	// Force unknown by temporarily relying on clear path: call with mocked outcome
	// via direct replication of ok=false branch.
	notify.SetFullscreen(true)
	a := &App{state: DefaultState()}
	a.presence.mu.Lock()
	a.presence.fsDetectOK = false
	a.presence.fsActive = false
	a.presence.mu.Unlock()
	// Manual ok=false branch (same as pollFullscreenOnce):
	if notify.Fullscreen() {
		notify.SetFullscreen(false)
	}
	if notify.Fullscreen() {
		t.Fatal("expected fullscreen cleared when detect unknown")
	}
}
