//go:build linux

package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func linuxConfigHome() (string, error) {
	if cfg := os.Getenv("XDG_CONFIG_HOME"); cfg != "" {
		return cfg, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config"), nil
}

func registerAutostartLinux(self string) error {
	cfg, err := linuxConfigHome()
	if err != nil {
		return err
	}
	dir := filepath.Join(cfg, "autostart")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	execLine := autostartExecLine(self)
	entry := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=DenyOut
Comment=Protect this computer / session
Exec=%s
Terminal=false
Categories=Security;Network;
X-GNOME-Autostart-enabled=true
`, execLine)
	if err := os.WriteFile(filepath.Join(dir, "denyout.desktop"), []byte(entry), 0o644); err != nil {
		return err
	}

	unitDir := filepath.Join(cfg, "systemd", "user")
	_ = os.MkdirAll(unitDir, 0o755)
	unit := fmt.Sprintf(`[Unit]
Description=DenyOut desktop tray
After=graphical-session.target

[Service]
Type=simple
ExecStart=%s
Restart=on-failure

[Install]
WantedBy=default.target
`, execLine)
	_ = os.WriteFile(filepath.Join(unitDir, "denyout-desktop.service"), []byte(unit), 0o644)
	return nil
}

func unregisterAutostartLinux() error {
	cfg, err := linuxConfigHome()
	if err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(cfg, "autostart", "denyout.desktop"))
	unitDir := filepath.Join(cfg, "systemd", "user")
	_ = os.Remove(filepath.Join(unitDir, "denyout-desktop.service"))
	_ = os.Remove(filepath.Join(unitDir, "denyout-desktop.service.off"))
	return nil
}

func autostartRegisteredLinux() bool {
	cfg, err := linuxConfigHome()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(cfg, "autostart", "denyout.desktop"))
	return err == nil
}

func detachCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
