//go:build windows

package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func registerAutostartWindows(self string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	startup := filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	if err := os.MkdirAll(startup, 0o755); err != nil {
		return err
	}
	cmdPath := filepath.Join(startup, "DenyOut.cmd")
	content := fmt.Sprintf("@echo off\r\nstart \"\" \"%s\" desktop\r\n", self)
	return os.WriteFile(cmdPath, []byte(content), 0o644)
}

func writeWindowsUserProxy(proxyURL, caFile string) error {
	_ = exec.Command("setx", "HTTP_PROXY", proxyURL).Run()
	_ = exec.Command("setx", "HTTPS_PROXY", proxyURL).Run()
	if caFile != "" {
		_ = exec.Command("setx", "SSL_CERT_FILE", caFile).Run()
		_ = exec.Command("setx", "NODE_EXTRA_CA_CERTS", caFile).Run()
	}
	return nil
}

func clearWindowsUserProxy() error {
	_ = exec.Command("setx", "HTTP_PROXY", "").Run()
	_ = exec.Command("setx", "HTTPS_PROXY", "").Run()
	return nil
}

func detachCmd(cmd *exec.Cmd) {
	const createNewProcessGroup = 0x00000200
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: createNewProcessGroup,
		HideWindow:    true,
	}
}
