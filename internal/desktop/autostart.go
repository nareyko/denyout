package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// RegisterAutostart installs login launch of `denyout` (or `denyout-cli desktop` for CLI-only).
func RegisterAutostart() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	self = preferStableDesktopBinary(self)
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

// preferStableDesktopBinary avoids writing go-test /tmp/go-build paths into login autostart.
func preferStableDesktopBinary(self string) string {
	base := filepath.Base(self)
	dir := filepath.Dir(self)
	tmp := filepath.Clean(os.TempDir())
	unstable := strings.HasSuffix(base, ".test") ||
		strings.Contains(base, ".test.") ||
		dir == tmp ||
		strings.HasPrefix(dir, tmp+string(os.PathSeparator))
	if !unstable {
		return self
	}
	// Prefer installed Wails `denyout` on PATH or under ~/.local/bin.
	if p, err := exec.LookPath("denyout"); err == nil {
		if resolved, err2 := filepath.EvalSymlinks(p); err2 == nil {
			return resolved
		}
		return p
	}
	if home, err := os.UserHomeDir(); err == nil {
		cand := filepath.Join(home, ".local", "bin", "denyout")
		if runtime.GOOS == "windows" {
			cand += ".exe"
		}
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand
		}
	}
	return self
}

// UnregisterAutostart removes login launch entries.
func UnregisterAutostart() error {
	switch runtime.GOOS {
	case "linux":
		return unregisterAutostartLinux()
	case "darwin":
		return unregisterAutostartDarwin()
	case "windows":
		return unregisterAutostartWindows()
	default:
		return nil
	}
}

// AutostartRegistered reports whether a login-launch entry is present on disk.
// Used so Settings reflects reality, not only the last saved preference.
func AutostartRegistered() bool {
	switch runtime.GOOS {
	case "linux":
		return autostartRegisteredLinux()
	case "darwin":
		return autostartRegisteredDarwin()
	case "windows":
		return autostartRegisteredWindows()
	default:
		return false
	}
}

// autostartExecLine returns the Exec=/ExecStart= value for login launch.
// Prefers sibling Wails `denyout` when present (same rule as DetachDesktop).
func autostartExecLine(self string) string {
	bin, args := desktopLaunchArgs(self)
	if len(args) == 0 {
		return bin
	}
	return bin + " " + strings.Join(args, " ")
}

// DetachDesktop starts `denyout` (preferred) or `denyout-cli desktop` in the background.
func DetachDesktop() error {
	return detachDesktop(false)
}

// DetachDesktopOpen starts the desktop shell and asks it to show the window (install path).
func DetachDesktopOpen() error {
	return detachDesktop(true)
}

func detachDesktop(openUI bool) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	bin, args := desktopLaunchArgs(self)
	if openUI {
		base := filepath.Base(bin)
		name := strings.TrimSuffix(base, filepath.Ext(base))
		if strings.EqualFold(name, "denyout") {
			args = append(args, "--open")
		}
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	// Drop ephemeral XDG_* from test/agent shells so the tray uses ~/.local/state.
	env := sanitizeDesktopEnv(os.Environ())
	if openUI {
		env = append(env, "DENYOUT_OPEN_UI=1")
	}
	cmd.Env = env
	detachCmd(cmd)
	return cmd.Start()
}

// desktopLaunchArgs prefers a sibling Wails `denyout` binary when present.
// The GUI binary is named exactly "denyout"; the CLI is "denyout-cli".
func desktopLaunchArgs(self string) (bin string, args []string) {
	base := filepath.Base(self)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	if strings.EqualFold(name, "denyout") {
		return self, nil
	}
	dir := filepath.Dir(self)
	cand := filepath.Join(dir, "denyout")
	if runtime.GOOS == "windows" {
		cand += ".exe"
	}
	if st, err := os.Stat(cand); err == nil && !st.IsDir() {
		return cand, nil
	}
	return self, []string{"desktop"}
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
