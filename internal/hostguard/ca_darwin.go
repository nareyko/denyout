//go:build darwin

package hostguard

import (
	"fmt"
	"os"
	"os/exec"
)

func installCA(certPath string) error {
	if certPath == "" {
		return fmt.Errorf("empty CA path")
	}
	if _, err := os.Stat(certPath); err != nil {
		return err
	}
	// Add to System keychain and trust for SSL.
	cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain", certPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("security add-trusted-cert: %w", err)
	}
	return nil
}

func uninstallCA() error {
	// Best-effort: remove by common name from System keychain (unverified in field notes).
	cmd := exec.Command("security", "delete-certificate", "-c", DesktopCANickname,
		"/Library/Keychains/System.keychain")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
	return nil
}

// caInstalled reports whether the DenyOut CA is in the System keychain (read-only query).
func caInstalled() bool {
	return exec.Command("security", "find-certificate", "-c", DesktopCANickname,
		"/Library/Keychains/System.keychain").Run() == nil
}
