//go:build linux

package hostguard

import (
	"fmt"
	"os"
	"strings"

	"github.com/nareyko/denyout/internal/privexec"
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
	if out, err := privexec.Output("nft", "-f", path); err != nil {
		return fmt.Errorf("nft apply: %w (need root / CAP_NET_ADMIN): %s", err, strings.TrimSpace(string(out)))
	}
	// Allow DenyOut to SO_MARK upstream dials so nft can skip them (needs setcap).
	if exe, err := os.Executable(); err == nil {
		privexec.Best("setcap", "cap_net_admin=ep", exe)
	}
	return nil
}

func removeRedirect(spec Spec) error {
	_ = spec
	privexec.Best("nft", "delete", "table", "ip", "denyout")
	privexec.Best("nft", "delete", "table", "inet", "denyout")
	return nil
}
