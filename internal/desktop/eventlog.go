package desktop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nareyko/denyout/internal/secrets"
)

const jsonlRotateBytes = 8 << 20 // 8 MiB

var eventLogMu sync.Mutex

// EventsLogPath is the product/lifecycle JSONL (pause, restore skip, quit, …).
func EventsLogPath() string {
	return filepath.Join(LogDir(), "events.jsonl")
}

// BlocksLogPath is the blocking/HITL JSONL (deny, ask, hard-block, …).
func BlocksLogPath() string {
	return filepath.Join(LogDir(), "blocks.jsonl")
}

// LogEvent appends one lifecycle event to events.jsonl and mirrors to desktop.log.
func LogEvent(name string, fields map[string]any) {
	appendJSONL(EventsLogPath(), "event", name, fields)
}

// LogBlock appends one blocking/HITL event to blocks.jsonl and mirrors to desktop.log.
func LogBlock(name string, fields map[string]any) {
	appendJSONL(BlocksLogPath(), "block", name, fields)
}

// logPolicyDeny records a policy deny (never a routine allow). source is proxyd|session|wrap.
func (a *App) logPolicyDeny(source, host string, reasons []string, url, process string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return
	}
	a.mu.Lock()
	ask := a.state.AskMode
	profile := normalizePolicyProfile(a.state.PolicyProfile)
	a.mu.Unlock()
	fields := map[string]any{
		"host":     host,
		"reasons":  reasons,
		"url":      secrets.RedactURL(strings.TrimSpace(url)),
		"profile":  profile,
		"ask_mode": ask,
		"source":   source,
	}
	if p := strings.TrimSpace(process); p != "" {
		fields["process"] = p
	}
	LogBlock("deny", fields)
	for _, r := range reasons {
		switch r {
		case "threat_list", "threat_phishing", "threat_malware", "threat_ads":
			LogBlock("threat_deny", map[string]any{
				"host": host, "reasons": reasons, "url": secrets.RedactURL(strings.TrimSpace(url)),
				"profile": profile, "source": source,
			})
		default:
			continue
		}
		break
	}
}

func appendJSONL(path, kind, name string, fields map[string]any) {
	eventLogMu.Lock()
	defer eventLogMu.Unlock()

	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	rotateJSONLIfLarge(path)

	rec := map[string]any{
		"ts":   time.Now().UTC().Format(time.RFC3339Nano),
		"type": name,
	}
	for k, v := range fields {
		if k == "ts" || k == "type" {
			continue
		}
		rec[k] = v
	}
	b, err := json.Marshal(rec)
	if err != nil {
		AppendDesktopLog("WARN %s=%s marshal: %v", kind, name, err)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		AppendDesktopLog("WARN %s=%s open: %v", kind, name, err)
		return
	}
	_, _ = f.Write(append(b, '\n'))
	_ = f.Close()
	AppendDesktopLog("INFO %s=%s %s", kind, name, string(b))
}

func rotateJSONLIfLarge(path string) {
	st, err := os.Stat(path)
	if err != nil || st.Size() < jsonlRotateBytes {
		return
	}
	bak := path + ".1"
	_ = os.Remove(bak)
	_ = os.Rename(path, bak)
}
