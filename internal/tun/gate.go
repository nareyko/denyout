package tun

import (
	"os"
	"strings"
)

// EnvE2E is the only opt-in that may attempt a real TUN device (VM dogfood).
// Default Protect and CI never set this.
const EnvE2E = "DENYOUT_TUN_E2E"

// WantDevice reports whether kernel TUN creation is allowed.
// Closed-loop default is false; requires DENYOUT_TUN_E2E=1.
func WantDevice() bool {
	return os.Getenv(EnvE2E) == "1"
}

// ActivePhase is the Protect dataplane phase. Production stays T0 until WantDevice
// and a future real tuntap implementation both land.
func ActivePhase() Phase {
	if WantDevice() {
		return PhaseT1UDP443
	}
	return PhaseT0NFTOnly
}

// SkipIfaceNames are interfaces that must never be stolen by a future TUN path
// (coexistence denylist — string contract only until VM dogfood).
func SkipIfaceNames() []string {
	return []string{
		"lo",
		"docker0",
		"br-",     // bridge prefix
		"veth",    // docker veth prefix
		"wg",      // WireGuard prefix
		"cloudflare",
		"tun0", // other VPNs; denyout0 is ours later
		"zt",   // ZeroTier prefix
		"tailscale",
	}
}

// ShouldSkipIface reports whether name matches the coexistence denylist.
func ShouldSkipIface(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" || n == DeviceName {
		return false
	}
	for _, s := range SkipIfaceNames() {
		switch s {
		case "br-", "veth", "wg", "zt":
			if strings.HasPrefix(n, s) {
				return true
			}
		case "cloudflare", "tailscale":
			if n == s || strings.HasPrefix(n, s) {
				return true
			}
		default:
			if n == s {
				return true
			}
		}
	}
	return false
}
