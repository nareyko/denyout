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
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		return err
	}
	// Replace prior table if present.
	_ = exec.Command("nft", "delete", "table", "ip", "denyout").Run()
	cmd := exec.Command("nft", "-f", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft apply: %w (need root / CAP_NET_ADMIN)", err)
	}
	return nil
}

func removeRedirect(spec Spec) error {
	_ = spec
	cmd := exec.Command("nft", "delete", "table", "ip", "denyout")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// Already gone is OK.
		return nil
	}
	return nil
}
