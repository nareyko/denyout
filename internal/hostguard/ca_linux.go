//go:build linux

package hostguard

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func installCA(certPath string) error {
	if certPath == "" {
		return fmt.Errorf("empty CA path")
	}
	if _, err := os.Stat(certPath); err != nil {
		return err
	}
	dstDir := "/usr/local/share/ca-certificates"
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		// Fallback: user NSS is harder; require root path.
		return fmt.Errorf("ca certs dir: %w", err)
	}
	dst := filepath.Join(dstDir, "denyout-desktop.crt")
	data, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return err
	}
	cmd := exec.Command("update-ca-certificates")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("update-ca-certificates: %w", err)
	}
	return nil
}
