package hostguard

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// QUICDropStats is the nft/pf counter for denyout-block-quic (Linux nft today).
type QUICDropStats struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
	// Present is false when the filter chain/rule is missing (AllowQUIC or Protect Off).
	Present bool `json:"present"`
	// Source is nft (T0 drop) or tun (T1 userspace); empty formats as nft.
	Source string `json:"source,omitempty"`
}

var reNFTCounterPacketsBytes = regexp.MustCompile(`(?i)counter\s+packets\s+(\d+)\s+bytes\s+(\d+)`)

// ParseQUICDropCounters extracts packets/bytes from `nft list` text for the QUIC drop rule.
func ParseQUICDropCounters(nftList string) QUICDropStats {
	var st QUICDropStats
	for _, line := range strings.Split(nftList, "\n") {
		if !strings.Contains(line, "denyout-block-quic") {
			continue
		}
		// nft prints: ... counter packets N bytes M drop comment "denyout-block-quic"
		if m := reNFTCounterPacketsBytes.FindStringSubmatch(line); len(m) == 3 {
			st.Packets, _ = strconv.ParseUint(m[1], 10, 64)
			st.Bytes, _ = strconv.ParseUint(m[2], 10, 64)
			st.Present = true
			return st
		}
		st.Present = true // rule exists but no counter yet (pre-counter apply)
		return st
	}
	return st
}

// FormatQUICDropStatsLine is the helper/hostctl response payload after OK.
func FormatQUICDropStatsLine(st QUICDropStats) string {
	src := st.Source
	if src == "" {
		src = "nft"
	}
	return fmt.Sprintf("packets=%d bytes=%d present=%t source=%s", st.Packets, st.Bytes, st.Present, src)
}

// QUICDropStatsBestEffort prefers the privileged helper, then a direct nft read (root).
func QUICDropStatsBestEffort(uid int) QUICDropStats {
	if st, err := HelperQUICStats(uid); err == nil {
		return st
	}
	st, err := ReadQUICDropStats()
	if err == nil {
		return st
	}
	return QUICDropStats{}
}

// ParseQUICDropStatsLine parses helper "OK quic1 packets=… bytes=… present=…" fields.
func ParseQUICDropStatsLine(resp string) (QUICDropStats, error) {
	var st QUICDropStats
	resp = strings.TrimSpace(resp)
	if !strings.HasPrefix(resp, "OK") {
		return st, fmt.Errorf("quic-stats: %s", resp)
	}
	st.Source = "nft" // default for T0-shaped lines without source=
	for _, f := range strings.Fields(resp) {
		switch {
		case strings.HasPrefix(f, "packets="):
			st.Packets, _ = strconv.ParseUint(strings.TrimPrefix(f, "packets="), 10, 64)
		case strings.HasPrefix(f, "bytes="):
			st.Bytes, _ = strconv.ParseUint(strings.TrimPrefix(f, "bytes="), 10, 64)
		case strings.HasPrefix(f, "present="):
			st.Present = strings.TrimPrefix(f, "present=") == "true" || strings.TrimPrefix(f, "present=") == "1"
		case strings.HasPrefix(f, "source="):
			st.Source = strings.TrimPrefix(f, "source=")
		}
	}
	return st, nil
}
