//go:build linux

package hostguard

import "testing"

func TestPathChainRootOwnedRejectsUserDir(t *testing.T) {
	// t.TempDir is owned by the (non-root) test user or is under a user-owned tree.
	if pathChainRootOwned(t.TempDir() + "/x") {
		t.Fatal("user temp path must not be trusted")
	}
	if !pathChainRootOwned("/usr/bin") && !pathChainRootOwned("/bin") {
		t.Skip("system dirs not root-clean in this environment")
	}
}
