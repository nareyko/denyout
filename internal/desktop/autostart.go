package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// RegisterAutostart installs login launch of `denyout desktop`.
func RegisterAutostart() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	switch runtime.GOOS {
	case "linux":
		return registerAutostartLinux(self)
	case "darwin":
		return registerAutostartDarwin(self)
	case "windows":
		return registerAutostartWindows(self)
	default:
		return fmt.Errorf("autostart: unsupported OS %s", runtime.GOOS)
	}
}

// DetachDesktop starts `denyout desktop` in the background and returns.
func DetachDesktop() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "desktop")
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	detachCmd(cmd)
	return cmd.Start()
}
