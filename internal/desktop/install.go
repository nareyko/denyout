package desktop

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/nareyko/denyout/internal/notify"
)

// Install performs silent desktop setup: autostart, try computer scope once,
// fall back to session, detach tray, return.
func Install(opts Options) error {
	st := LoadState()
	st.SetupDone = true
	st.Notify = true
	st.AskMode = false
	st.ComputerAvailable = true
	if err := SaveState(st); err != nil {
		return err
	}
	notify.SetEnabled(true)

	if err := RegisterAutostart(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout install: autostart: %v\n", err)
	} else {
		fmt.Fprintln(os.Stderr, "denyout install: login autostart registered")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := &App{opts: opts, state: LoadState(), status: "Off"}
	if _, err := a.startControlServer(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "denyout install: control server: %v\n", err)
	}

	scope := ScopeSession
	avail := true
	fmt.Fprintln(os.Stderr, "denyout install: trying Protect whole computer (admin may be required)…")
	if err := a.startComputer(); err != nil {
		fmt.Fprintf(os.Stderr, "denyout install: computer mode unavailable: %v\n", err)
		avail = false
		if err := a.startSession(); err != nil {
			fmt.Fprintf(os.Stderr, "denyout install: session mode failed: %v\n", err)
			scope = ScopeOff
		} else {
			scope = ScopeSession
			fmt.Fprintln(os.Stderr, "denyout install: running in Session mode (proxy; no admin)")
			notify.Info("DenyOut", "Session mode (no admin). Use tray → Protect whole computer for full protection.")
		}
	} else {
		scope = ScopeComputer
		fmt.Fprintln(os.Stderr, "denyout install: Protect whole computer is on")
	}

	// Tear down this process's protectors; tray will restore from state.
	a.stopAll()
	cancel()
	time.Sleep(150 * time.Millisecond)

	st = LoadState()
	st.SetupDone = true
	st.Scope = scope
	st.ComputerAvailable = avail
	st.ProtectionOn = scope == ScopeComputer || scope == ScopeSession
	st.ComputerEnabled = scope == ScopeComputer
	_ = SaveState(st)

	if err := DetachDesktop(); err != nil {
		return fmt.Errorf("start tray: %w", err)
	}
	fmt.Fprintf(os.Stderr, "denyout install: done (scope=%s protection_on=%v computer_available=%v)\n",
		st.Scope, st.ProtectionOn, st.ComputerAvailable)
	return nil
}
