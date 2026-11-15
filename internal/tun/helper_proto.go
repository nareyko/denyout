package tun

import (
	"fmt"
	"strings"
)

// CapTag is the helper capability marker for TUN verb support (like quic1).
const CapTag = "tun1"

// IsHelperVerb reports whether verb is a reserved T1 helper control word.
func IsHelperVerb(verb string) bool {
	switch strings.ToLower(strings.TrimSpace(verb)) {
	case "tun-start", "tun-stop", "tun-stats":
		return true
	default:
		return false
	}
}

// HelperReply returns the closed-loop helper response for a TUN verb.
// Never opens a device: enabled=false until VM dogfood lands real tuntap.
func HelperReply(verb string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(verb))
	if !IsHelperVerb(v) {
		return "", fmt.Errorf("tun: unknown helper verb %q", verb)
	}
	switch v {
	case "tun-stats":
		return "OK " + CapTag + " " + FormatDropStatsLine(DropStats{
			Present: false,
			Source:  SourceTUN,
		}), nil
	default:
		// tun-start / tun-stop: acknowledge protocol, refuse kernel work.
		return fmt.Sprintf("OK %s enabled=false verb=%s", CapTag, v), nil
	}
}

// ParseHelperReply parses an OK tun1 … response (start/stop/stats).
type HelperStatus struct {
	Enabled bool
	Verb    string
	Stats   DropStats
	RawOK   bool
}

// ParseHelperReply understands disabled stubs and stats lines.
func ParseHelperReply(resp string) (HelperStatus, error) {
	var st HelperStatus
	resp = strings.TrimSpace(resp)
	if !strings.HasPrefix(resp, "OK") {
		return st, fmt.Errorf("tun helper: %s", resp)
	}
	st.RawOK = true
	fields := strings.Fields(resp)
	for _, f := range fields {
		switch {
		case f == CapTag:
			// capability tag
		case strings.HasPrefix(f, "enabled="):
			v := strings.TrimPrefix(f, "enabled=")
			st.Enabled = v == "true" || v == "1"
		case strings.HasPrefix(f, "verb="):
			st.Verb = strings.TrimPrefix(f, "verb=")
		case strings.HasPrefix(f, "packets="), strings.HasPrefix(f, "bytes="),
			strings.HasPrefix(f, "present="), strings.HasPrefix(f, "source="):
			// filled via ParseDropStatsLine below
		}
	}
	if strings.Contains(resp, "packets=") {
		ds, err := ParseDropStatsLine(resp)
		if err != nil {
			return st, err
		}
		st.Stats = ds
	}
	return st, nil
}
