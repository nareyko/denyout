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
	name := DesktopCANickname
	_ = exec.Command(certutil, "-d", db, "-D", "-n", name).Run()
	cmd := exec.Command(certutil, "-d", db, "-A", "-t", "C,,", "-n", name, "-i", certPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nss trust: %w (%s)", err, string(out))
	}
	return nil
}

// UntrustCAForUserBrowsers removes the DenyOut CA from the user NSS DB.
func UntrustCAForUserBrowsers() error {
	certutil, err := exec.LookPath("certutil")
	if err != nil {
		return nil // no NSS tools = nothing to untrust
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	nssDir := filepath.Join(home, ".pki", "nssdb")
	if _, err := os.Stat(filepath.Join(nssDir, "cert9.db")); err != nil {
		return nil
	}
	db := "sql:" + nssDir
	cmd := exec.Command(certutil, "-d", db, "-D", "-n", DesktopCANickname)
	_ = cmd.Run() // already absent is OK
	return nil
}
