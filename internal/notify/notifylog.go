package notify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const notifyLogRotateBytes = 8 << 20

var (
	logMu   sync.Mutex
	logPath string // empty = disabled (tests until SetLogPath)
)

// SetLogPath sets the notify.jsonl path (call from desktop Bootstrap). Empty disables.
func SetLogPath(path string) {
	logMu.Lock()
	logPath = path
	logMu.Unlock()
}

func logAttempt(kind Kind, title, body string, shown bool, reason, lvl string, isAway, focused, fs, snoozed bool) {
	logMu.Lock()
	path := logPath
	logMu.Unlock()
	if path == "" {
		return
	}
	if len(body) > 400 {
		body = body[:400] + "…"
	}
	rec := map[string]any{
		"ts":         time.Now().UTC().Format(time.RFC3339Nano),
		"kind":       string(kind),
		"title":      title,
		"body":       body,
		"shown":      shown,
		"reason":     reason,
		"level":      lvl,
		"away":       isAway,
		"ui_focused": focused,
		"fullscreen": fs,
		"snoozed":    snoozed,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	if st, err := os.Stat(path); err == nil && st.Size() >= notifyLogRotateBytes {
		bak := path + ".1"
		_ = os.Remove(bak)
		_ = os.Rename(path, bak)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
	_ = f.Close()
}
