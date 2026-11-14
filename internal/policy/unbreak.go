package policy

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed unbreak_hosts.txt
var unbreakHostsFile string

var (
	unbreakOnce sync.Once
	unbreakList []string
)

// DefaultUnbreakHosts returns the embedded Book D product exceptions
// (exact hosts and *.suffix patterns). Always on; not user-editable.
func DefaultUnbreakHosts() []string {
	unbreakOnce.Do(func() {
		unbreakList = parseUnbreakFile(unbreakHostsFile)
	})
	out := make([]string, len(unbreakList))
	copy(out, unbreakList)
	return out
}

// UnbreakCount is len(DefaultUnbreakHosts()) without copying.
func UnbreakCount() int {
	return len(DefaultUnbreakHosts())
}

// UnbreakSkipsThreat reports whether Book D covers host for threat-list purposes.
func UnbreakSkipsThreat(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	for _, p := range DefaultUnbreakHosts() {
		if HostMatch(p, host) {
			return true
		}
	}
	return false
}

func parseUnbreakFile(raw string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		line = normalizeHost(line)
		if line == "" {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	return out
}
