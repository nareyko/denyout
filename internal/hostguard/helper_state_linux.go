//go:build linux

package hostguard

import (
	"os"
	"path/filepath"

	"github.com/nareyko/denyout/internal/privexec"
)

var helperSpecFile = filepath.Join(helperStateDir, "helper_state.json")

func persistHelperState(spec Spec) {
	b, err := encodeHelperStatePolicy(spec, ConfiguredFailPolicy())
	if err != nil {
		return
	}
	_ = os.MkdirAll(helperStateDir, 0o755)
	tmp, err := os.CreateTemp(helperStateDir, ".helper_state-*")
	if err != nil {
		return
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return
	}
	if tmp.Close() == nil {
		_ = os.Rename(name, helperSpecFile)
	}
}

func forgetHelperState() { _ = os.Remove(helperSpecFile) }

// reconcileHelperOnStart restores full protection after a helper crash/restart.
//
// The state file exists only while Protect is meant to be On (clean Protect Off and
// SIGTERM remove it). If it exists AND our nft table is still in the kernel, the helper
// died abnormally, possibly leaving the TUN-suppressed ruleset (IPv4 redirect gone):
// re-apply the full non-suppressed ruleset from the persisted intent. If the table is
// gone (reboot) nothing is applied, so boot never silently turns Protect on.
func reconcileHelperOnStart(ownerUID int) {
	b, err := os.ReadFile(helperSpecFile)
	if err != nil {
		return
	}
	spec, err := decodeHelperState(b, ownerUID)
	if err != nil {
		forgetHelperState()
		return
	}
	if p := decodeHelperFailPolicy(b); p != "" {
		SetFailPolicy(p)
	}
	if _, err := privexec.Output("nft", "list", "table", "inet", "denyout"); err != nil {
		forgetHelperState() // rules are gone: nothing to restore
		return
	}
	if err := Apply(spec); err != nil {
		return
	}
	lastApplyMu.Lock()
	lastApplySpec, lastApplyOK, tunSuppressed = spec, true, false
	lastApplyMu.Unlock()
	writeHelperState("protected restored_after_restart")
}
