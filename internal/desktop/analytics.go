package desktop

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LocalAnalytics is the History “This week” payload (local JSONL only; no upload).
type LocalAnalytics struct {
	Days            int                  `json:"days"`
	Blocked         int                  `json:"blocked"`
	YouAllowed      int                  `json:"you_allowed"`
	Asked           int                  `json:"asked"`
	QuietWeek       bool                 `json:"quiet_week"`
	ProtectTimeline []AnalyticsTimeline  `json:"protect_timeline"`
	BannersShown    int                  `json:"banners_shown"`
	BannersHeldBack int                  `json:"banners_held_back"`
	PrivacyNote     string               `json:"privacy_note"`
}

// AnalyticsTimeline is one Protect lifecycle line for the UI.
type AnalyticsTimeline struct {
	Ts   string `json:"ts"`
	Type string `json:"type"`
	Note string `json:"note,omitempty"`
}

// GetLocalAnalytics aggregates blocks/events/notify JSONL for the last days (default 7).
func (a *App) GetLocalAnalytics(days int) LocalAnalytics {
	if days <= 0 {
		days = 7
	}
	if days > 90 {
		days = 90
	}
	since := time.Now().UTC().AddDate(0, 0, -days)
	out := LocalAnalytics{
		Days:        days,
		PrivacyNote: "Stays on this computer. Nothing is uploaded.",
	}

	cutoff := since
	scanJSONL(BlocksLogPath(), func(rec map[string]any) {
		if !recAfter(rec, cutoff) {
			return
		}
		switch typ := asString(rec["type"]); typ {
		case "deny", "threat_deny":
			out.Blocked++
		case "always_allow_add", "timed_allow", "allow_once", "bulk_always_allow", "pack_allow":
			out.YouAllowed++
		case "ask_shown":
			out.Asked++
		case "hardblock_answered":
			act := asString(rec["action"])
			if act == DecisionAllow || strings.HasPrefix(act, DecisionAllowTimed) {
				out.YouAllowed++
			}
		}
	})

	scanJSONL(EventsLogPath(), func(rec map[string]any) {
		if !recAfter(rec, cutoff) {
			return
		}
		typ := asString(rec["type"])
		switch typ {
		case "protect_on", "protect_off", "protect_pause", "restore_skipped", "launch_offer_protect", "quit":
			if len(out.ProtectTimeline) >= 12 {
				return
			}
			note := ""
			if r, ok := rec["reason"]; ok {
				note = asString(r)
			}
			if c, ok := rec["choice"]; ok && note == "" {
				note = asString(c)
			}
			out.ProtectTimeline = append(out.ProtectTimeline, AnalyticsTimeline{
				Ts:   asString(rec["ts"]),
				Type: typ,
				Note: note,
			})
		}
	})

	notifyPath := filepath.Join(LogDir(), "notify.jsonl")
	scanJSONL(notifyPath, func(rec map[string]any) {
		if !recAfter(rec, cutoff) {
			return
		}
		if shown, ok := rec["shown"].(bool); ok && shown {
			out.BannersShown++
		} else {
			out.BannersHeldBack++
		}
	})

	out.QuietWeek = out.Blocked == 0 && out.YouAllowed == 0 && out.Asked == 0
	return out
}

func scanJSONL(path string, fn func(map[string]any)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	// Large deny lines possible; raise buffer.
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		fn(rec)
	}
}

func recAfter(rec map[string]any, since time.Time) bool {
	ts := asString(rec["ts"])
	if ts == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		t, err = time.Parse(time.RFC3339, ts)
	}
	if err != nil {
		return true
	}
	return !t.Before(since)
}

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	default:
		return ""
	}
}
