//go:build linux

package hostguard

import (
	"os"

	"github.com/nareyko/denyout/internal/protectstate"
)

// HelperDegraded reports whether the helper watchdog has removed the redirect
// because the proxy stopped answering (fail-soft). Protect is then NOT filtering.
func HelperDegraded() bool {
	b, err := os.ReadFile(helperStateFile)
	if err != nil {
		return false
	}
	return protectstate.HelperStateDegraded(string(b))
}
