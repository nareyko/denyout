package hostguard

import (
	"fmt"
	"time"
)

// EnsureHelperFresh checks helper caps and reinstalls the unit once if stale.
// Safe to call after Protect On ElevateApply. Returns whether a refresh ran.
func EnsureHelperFresh(ownerUID int) (refreshed bool, caps CapsReply, err error) {
	if ElevateDisabledByEnv() {
		return false, CapsReply{}, nil
	}
	caps, err = HelperCaps()
	if err == nil {
		miss := caps.MissingRequired(RequiredProtectCaps)
		if len(miss) == 0 {
			return false, caps, nil
		}
		err = ErrStaleHelperCaps(miss)
	}
	// Refresh: elevate install copies current binary into the unit ExecStart.
	if ierr := ElevateInstallHelper(ownerUID); ierr != nil {
		return false, caps, fmt.Errorf("helper refresh: %v (prior: %v)", ierr, err)
	}
	refreshed = true
	// Brief wait for systemd restart / socket listen.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		caps2, cerr := HelperCaps()
		if cerr == nil && len(caps2.MissingRequired(RequiredProtectCaps)) == 0 {
			return true, caps2, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	caps2, cerr := HelperCaps()
	if cerr != nil {
		return true, caps, fmt.Errorf("helper refresh installed but caps still unavailable: %v", cerr)
	}
	if miss := caps2.MissingRequired(RequiredProtectCaps); len(miss) > 0 {
		return true, caps2, ErrStaleHelperCaps(miss)
	}
	return true, caps2, nil
}
