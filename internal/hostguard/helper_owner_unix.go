//go:build !windows

package hostguard

import (
	"os"
	"syscall"
)

// fileOwnedByOrRoot reports whether fi is owned by ownerUID or root.
func fileOwnedByOrRoot(fi os.FileInfo, ownerUID int) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	return int(st.Uid) == ownerUID || st.Uid == 0
}
