//go:build linux

package hostguard

import (
	"fmt"
	"strings"

	"github.com/nareyko/denyout/internal/privexec"
)

// ReadQUICDropStats reads the live nft counter for denyout-block-quic (needs CAP_NET_ADMIN / root).
func ReadQUICDropStats() (QUICDropStats, error) {
	out, err := privexec.Output("nft", "list", "chain", "inet", "denyout", "output_filter")
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		low := strings.ToLower(msg)
		// Missing table/chain = Protect Off or AllowQUIC — not an error for callers.
		if strings.Contains(low, "no such file") ||
			strings.Contains(low, "does not exist") ||
			strings.Contains(low, "could not find") ||
			strings.Contains(low, "not found") {
			return QUICDropStats{}, nil
		}
		return QUICDropStats{}, fmt.Errorf("nft list quic chain: %s", msg)
	}
	return ParseQUICDropCounters(string(out)), nil
}
