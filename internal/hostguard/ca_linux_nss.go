//go:build linux

package hostguard

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// TrustCAForUserBrowsers installs the DenyOut CA into the current user's NSS DB
// (~/.pki/nssdb) so Chrome / Chromium / Electron trust MITM certs.
// System update-ca-certificates alone is not enough for those browsers.
func TrustCAForUserBrowsers(certPath string) error {
	if certPath == "" {
		return fmt.Errorf("empty CA path")
	}
	if _, err := os.Stat(certPath); err != nil {
		return err
	}
	certutil, err := exec.LookPath("certutil")
	if err != nil {
		return fmt.Errorf("certutil not found (install libnss3-tools): %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	nssDir := filepath.Join(home, ".pki", "nssdb")
	if err := os.MkdirAll(nssDir, 0o700); err != nil {
		return err
	}
	db := "sql:" + nssDir
	// Ensure DB exists (empty password).
	if _, err := os.Stat(filepath.Join(nssDir, "cert9.db")); err != nil {
		init := exec.Command(certutil, "-N", "-d", db, "--empty-password")
		_ = init.Run()
	}
	name := "DenyOut Desktop CA"
	_ = exec.Command(certutil, "-d", db, "-D", "-n", name).Run()
	cmd := exec.Command(certutil, "-d", db, "-A", "-t", "C,,", "-n", name, "-i", certPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nss trust: %w (%s)", err, string(out))
	}
	return nil
}
