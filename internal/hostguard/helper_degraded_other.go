//go:build !linux

package hostguard

// HelperDegraded is Linux-only (the watchdog lives in the Linux helper).
func HelperDegraded() bool { return false }
