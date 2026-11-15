package desktop

import (
	"strings"

	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/tun"
)

// ensureTunAfterProtectOn is the Protect On lifecycle hook for T1.
// Default: log tun_start_skipped (T0 nft path). Only with DENYOUT_TUN_E2E=1
// does it call tun-start — and today's helper still replies enabled=false.
func ensureTunAfterProtectOn(uid int) {
	fields := map[string]any{
		"uid":   uid,
		"phase": string(tun.ActivePhase()),
	}
	if !tun.WantDevice() {
		fields["reason"] = "flag_off"
		LogEvent("tun_start_skipped", fields)
		return
	}
	line, err := hostguard.HelperTunCall("tun-start", uid)
	if err != nil {
		fields["err"] = err.Error()
		LogEvent("tun_start", fields)
		return
	}
	fields["reply"] = line
	if st, perr := tun.ParseHelperReply(line); perr == nil {
		fields["enabled"] = st.Enabled
	}
	LogEvent("tun_start", fields)
}

// ensureTunStopped is the Protect Off lifecycle hook for T1.
// Closed-loop: calls the helper/local stub (enabled=false); never opens a TUN.
func ensureTunStopped(uid int) {
	line, err := hostguard.HelperTunCall("tun-stop", uid)
	fields := map[string]any{"uid": uid}
	if err != nil {
		fields["err"] = err.Error()
		LogEvent("tun_stop", fields)
		return
	}
	fields["reply"] = line
	if st, perr := tun.ParseHelperReply(line); perr == nil {
		fields["enabled"] = st.Enabled
		fields["cap"] = tun.CapTag
	}
	LogEvent("tun_stop", fields)
}

func logQuicDropStats(reason string) {
	uid, _ := hostguard.CurrentUID()
	st := hostguard.QUICDropStatsBestEffort(uid)
	src := st.Source
	if strings.TrimSpace(src) == "" {
		src = "nft"
	}
	LogEvent("quic_drop_stats", map[string]any{
		"reason":  reason,
		"packets": st.Packets,
		"bytes":   st.Bytes,
		"present": st.Present,
		"source":  src,
	})
	// Snapshot TUN stub counters too (always present=false until real device).
	if line, err := hostguard.HelperTunCall("tun-stats", uid); err == nil {
		if ts, perr := tun.ParseHelperReply(line); perr == nil {
			LogEvent("tun_drop_stats", map[string]any{
				"reason":  reason,
				"packets": ts.Stats.Packets,
				"bytes":   ts.Stats.Bytes,
				"present": ts.Stats.Present,
				"source":  string(ts.Stats.Source),
			})
		}
	}
	ensureTunStopped(uid)
}
