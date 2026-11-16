package hostguard

import (
	"fmt"
	"strings"
)

// Helper capability tags advertised by a current helper-serve.
const (
	CapQUIC = "quic1"
	CapTUN  = "tun1"
	CapVPN  = "vpn1"
	CapCaps = "caps1" // helper understands the caps verb itself
)

// RequiredProtectCaps are the minimum tags Protect On expects after refresh.
var RequiredProtectCaps = []string{CapQUIC, CapTUN}

// CapsReply is a parsed OK caps … line.
type CapsReply struct {
	OK      bool
	Caps    []string
	Version string // optional denyout version / build id
	Raw     string
}

// FormatCapsReply builds the helper response for verb "caps".
func FormatCapsReply(version string, caps ...string) string {
	parts := []string{"OK", "caps", CapCaps}
	parts = append(parts, caps...)
	if v := strings.TrimSpace(version); v != "" {
		parts = append(parts, "version="+sanitizeCapToken(v))
	}
	return strings.Join(parts, " ")
}

func sanitizeCapToken(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " ", "_")
	return s
}

// ParseCapsReply parses "OK caps caps1 quic1 tun1 …" (or legacy plain OK).
func ParseCapsReply(resp string) CapsReply {
	resp = strings.TrimSpace(resp)
	out := CapsReply{Raw: resp}
	if !strings.HasPrefix(resp, "OK") {
		return out
	}
	out.OK = true
	fields := strings.Fields(resp)
	for _, f := range fields {
		switch {
		case f == "OK" || f == "caps":
			continue
		case strings.HasPrefix(f, "version="):
			out.Version = strings.TrimPrefix(f, "version=")
		default:
			out.Caps = append(out.Caps, f)
		}
	}
	return out
}

// HasCap reports whether reply includes tag.
func (c CapsReply) HasCap(tag string) bool {
	for _, x := range c.Caps {
		if x == tag {
			return true
		}
	}
	return false
}

// MissingRequired returns required tags not present in the reply.
func (c CapsReply) MissingRequired(required []string) []string {
	var miss []string
	for _, r := range required {
		if !c.HasCap(r) {
			miss = append(miss, r)
		}
	}
	return miss
}

// CapsSatisfied is true when all required tags are present.
func CapsSatisfied(resp string, required []string) bool {
	c := ParseCapsReply(resp)
	if !c.OK {
		return false
	}
	return len(c.MissingRequired(required)) == 0
}

// ErrStaleHelperCaps means the helper is reachable but too old.
func ErrStaleHelperCaps(missing []string) error {
	return fmt.Errorf("%w: missing caps %s", ErrHelperUnavailable, strings.Join(missing, ","))
}
