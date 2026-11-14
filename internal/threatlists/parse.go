package threatlists

import (
	"bufio"
	"bytes"
	"strings"
	"unicode"
)

// Parse extracts hostnames from raw list bytes according to format.
// Comments (#, !) and blank lines are skipped. Domains are lowercased
// and trailing dots stripped. Returns a de-duplicated set.
func Parse(raw []byte, format Format) map[string]struct{} {
	out := make(map[string]struct{})
	sc := bufio.NewScanner(bytes.NewReader(raw))
	// Some hosts files are large; raise token size.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || isComment(line) {
			continue
		}
		switch format {
		case FormatHosts:
			for _, h := range parseHostsLine(line) {
				addHost(out, h)
			}
		case FormatABP:
			if h, ok := parseABPLine(line); ok {
				addHost(out, h)
			}
		default: // FormatDomains and unknown → treat as domains
			if h, ok := parseDomainLine(line); ok {
				addHost(out, h)
			}
		}
	}
	return out
}

func isComment(line string) bool {
	return strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!")
}

func addHost(out map[string]struct{}, h string) {
	h = normalizeHost(h)
	if h == "" || !looksLikeHost(h) {
		return
	}
	out[h] = struct{}{}
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.Trim(h, ".")
	h = strings.ToLower(h)
	return h
}

func looksLikeHost(h string) bool {
	if h == "" || strings.ContainsAny(h, " \t/") {
		return false
	}
	h = strings.TrimPrefix(h, "*.")
	if !strings.Contains(h, ".") {
		return false
	}
	for _, r := range h {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func parseDomainLine(line string) (string, bool) {
	// Strip trailing inline comments.
	if i := strings.IndexAny(line, "#!"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}
	// Reject accidental hosts-style lines in domain files.
	fields := strings.Fields(line)
	if len(fields) != 1 {
		return "", false
	}
	return fields[0], true
}

func parseHostsLine(line string) []string {
	if i := strings.IndexAny(line, "#"); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}
	// fields[0] is IP; rest may be multiple hostnames.
	return append([]string(nil), fields[1:]...)
}

// parseABPLine accepts simple ||domain^ (optional trailing options ignored).
func parseABPLine(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "||") {
		return "", false
	}
	rest := line[2:]
	end := strings.IndexAny(rest, "^$")
	if end < 0 {
		return "", false
	}
	host := rest[:end]
	// Skip path-ish or wildcard-heavy rules.
	if strings.ContainsAny(host, "*/") {
		return "", false
	}
	return host, true
}
