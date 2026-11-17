//go:build linux

package hostguard

import (
	"fmt"
	"github.com/nareyko/denyout/internal/privexec"
	"os"
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
	dst := filepath.Join(dstDir, "denyout.crt")
	data, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return err
	}
	if err := privexec.Run("update-ca-certificates"); err != nil {
		return fmt.Errorf("update-ca-certificates: %w", err)
	}
	return nil
}

// uninstallCA removes the system CA installed by installCA and refreshes the store.
func uninstallCA() error {
	_ = os.Remove(LinuxSystemCACert)
	privexec.Best("update-ca-certificates") // best-effort; still clear dangling hash link
	_ = os.Remove(LinuxSystemCAHashLink)
	return nil
}
