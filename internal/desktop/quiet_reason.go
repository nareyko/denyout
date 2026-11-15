package desktop

import (
	"strings"
	"time"
)

// formatQuietReason builds the shared "Quiet · …" phrase for Home, chrome, and tray.
// parts: away | fullscreen | snoozed (order preserved).
// snoozeUntilRFC is used only when "snoozed" is in parts.
func formatQuietReason(parts []string, snoozeUntilRFC string) string {
	if len(parts) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Quiet")
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == "" {
			continue
		}
		if p == "snoozed" {
			b.WriteString(" · snoozed")
			if label := formatQuietSnoozeUntil(snoozeUntilRFC); label != "" {
				b.WriteString(" until ")
				b.WriteString(label)
			}
			continue
		}
		b.WriteString(" · ")
		b.WriteString(p)
	}
	if b.Len() <= len("Quiet") {
		return ""
	}
	return b.String()
}

func formatQuietSnoozeUntil(rfc string) string {
	rfc = strings.TrimSpace(rfc)
	if rfc == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, rfc)
	if err != nil {
		return ""
	}
	local := t.Local()
	now := time.Now().Local()
	if local.Format("2006-01-02") == now.Format("2006-01-02") {
		return local.Format("15:04")
	}
	tomorrow := now.Add(24 * time.Hour)
	if local.Format("2006-01-02") == tomorrow.Format("2006-01-02") {
		return "tomorrow " + local.Format("15:04")
	}
	return local.Format("Jan 2, 15:04")
}

// quietReasonLocked returns the shared phrase while caller holds a.mu (or is single-threaded in tests).
func (a *App) quietReasonLocked() string {
	var parts []string
	if a.isAwayLocked() {
		parts = append(parts, "away")
	}
	if a.isFullscreenQuiet() {
		parts = append(parts, "fullscreen")
	}
	until := activeNotifySnoozeUntil(a.state.NotifySnoozeUntil)
	if until != "" {
		parts = append(parts, "snoozed")
	}
	return formatQuietReason(parts, until)
}

// quietReason returns the shared phrase (takes locks).
func (a *App) quietReason() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.quietReasonLocked()
}
