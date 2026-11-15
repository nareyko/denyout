//go:build linux

package hostguard

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// ReadQUICDropStats reads the live nft counter for denyout-block-quic (needs CAP_NET_ADMIN / root).
func ReadQUICDropStats() (QUICDropStats, error) {
	cmd := exec.Command("nft", "list", "chain", "inet", "denyout", "output_filter")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		low := strings.ToLower(msg + " " + stdout.String())
		// Missing table/chain = Protect Off or AllowQUIC — not an error for callers.
		if strings.Contains(low, "no such file") ||
			strings.Contains(low, "does not exist") ||
			strings.Contains(low, "could not find") ||
			strings.Contains(low, "not found") {
			return QUICDropStats{}, nil
		}
		return QUICDropStats{}, fmt.Errorf("nft list quic chain: %s", msg)
	}
	return ParseQUICDropCounters(stdout.String()), nil
}
