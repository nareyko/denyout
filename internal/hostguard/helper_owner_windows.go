//go:build windows

package hostguard

import "os"

// Windows has no uid ownership; the Linux helper (the only caller) is not used here.
func fileOwnedByOrRoot(os.FileInfo, int) bool { return true }
