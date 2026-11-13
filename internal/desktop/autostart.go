package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
	// Drop ephemeral XDG_* from test/agent shells so the tray uses ~/.local/state.
	cmd.Env = sanitizeDesktopEnv(os.Environ())
	detachCmd(cmd)
	return cmd.Start()
}

// sanitizeDesktopEnv removes XDG_STATE_HOME / XDG_CONFIG_HOME when they point
// under the process temp dir (common in CI/agent harnesses). Keeps intentional
// user overrides outside /tmp.
func sanitizeDesktopEnv(env []string) []string {
	tmp := filepath.Clean(os.TempDir())
	out := make([]string, 0, len(env))
	for _, e := range env {
		key, val, ok := strings.Cut(e, "=")
		if !ok {
			out = append(out, e)
			continue
		}
		switch key {
		case "XDG_STATE_HOME", "XDG_CONFIG_HOME":
			clean := filepath.Clean(val)
			if clean == tmp || strings.HasPrefix(clean, tmp+string(os.PathSeparator)) {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}
