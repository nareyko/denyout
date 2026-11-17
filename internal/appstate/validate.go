package appstate

import (
	"net"
	"strings"
)

// ValidAlwaysAllowHost reports whether h has the shape the cloud-sync path accepts
// for an always-allow entry: a plain DNS name with at least one dot (no wildcard,
// scheme, port, IP literal or bare TLD).
func ValidAlwaysAllowHost(h string) bool {
	h = strings.ToLower(strings.TrimSpace(h))
	return len(h) <= 253 && syncHostRE.MatchString(h) && net.ParseIP(h) == nil
}
