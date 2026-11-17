//go:build linux

package hostguard

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func applyRedirect(spec Spec) error {
	rules := renderLinuxNFT(spec)
	dir, err := os.MkdirTemp("", "denyout-nft-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "denyout.nft")
	// One nft transaction: "add" makes the following "delete" idempotent, and the
	// whole file applies atomically, so a failed load never leaves the user with
	// no rules (previously: delete first, then load).
	script := "add table ip denyout\ndelete table ip denyout\n" +
		"add table inet denyout\ndelete table inet denyout\n" + rules
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		return err
	}
	cmd := exec.Command("nft", "-f", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft apply: %w (need root / CAP_NET_ADMIN)", err)
	}
	// Allow DenyOut to SO_MARK upstream dials so nft can skip them (needs setcap).
	if exe, err := os.Executable(); err == nil {
		_ = exec.Command("setcap", "cap_net_admin=ep", exe).Run()
	}
	return nil
}

func removeRedirect(spec Spec) error {
	_ = spec
	_ = exec.Command("nft", "delete", "table", "ip", "denyout").Run()
	_ = exec.Command("nft", "delete", "table", "inet", "denyout").Run()
	return nil
}
