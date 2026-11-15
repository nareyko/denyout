package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const envDetached = "DENYOUT_DETACHED"

// ReexecDetachedIfTTY re-launches this process in the background when stdout is
// a terminal. The parent prints one line and exits 0; the child inherits args
// and sets DENYOUT_DETACHED=1. No-op when already detached, not a TTY, or when
// skip is true (--foreground / --no-tray).
//
// Install/autostart already use DetachDesktop (Setsid + closed stdio); those
// children never hit this path.
func ReexecDetachedIfTTY(skip bool) {
	if skip || os.Getenv(envDetached) == "1" {
		return
	}
	fi, err := os.Stdout.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return
	}
	self, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	cmd := exec.Command(self, os.Args[1:]...)
	cmd.Env = append(os.Environ(), envDetached+"=1")
	cmd.Stdin = nil
	logFile := openDesktopLogAppend()
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	} else {
		cmd.Stdout = nil
		cmd.Stderr = nil
	}
	detachCmd(cmd)
	if err := cmd.Start(); err != nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		fmt.Fprintf(os.Stderr, "denyout: could not detach (%v) — staying in this terminal\n", err)
		return
	}
	if logFile != nil {
		_ = logFile.Close() // child keeps its inherited copy
	}
	fmt.Fprintln(os.Stderr, "denyout: started in background (tray). Use --foreground to keep this terminal.")
	os.Exit(0)
}

func openDesktopLogAppend() *os.File {
	_ = os.MkdirAll(LogDir(), 0o755)
	f, err := os.OpenFile(DesktopLogPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil
	}
	return f
}
