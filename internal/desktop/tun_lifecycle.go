package desktop

import (
	"runtime"
	"strings"

	"github.com/nareyko/denyout/internal/hostguard"
	"github.com/nareyko/denyout/internal/tun"
)

// tunGateOn reports whether Protect On should request real tun-start.
func (a *App) tunGateOn() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if tun.WantDevice() {
		return true
	}
	a.mu.Lock()
	on := a.state.TunDataplane
	a.mu.Unlock()
	return on
}

// ensureHelperFreshAfterProtectOn refreshes a stale hostguard helper binary/caps.
func ensureHelperFreshAfterProtectOn(uid int) {
	refreshed, caps, err := hostguard.EnsureHelperFresh(uid)
	fields := map[string]any{
		"uid":       uid,
		"refreshed": refreshed,
		"caps":      strings.Join(caps.Caps, ","),
		"version":   caps.Version,
	}
	if err != nil {
		fields["err"] = err.Error()
	}
	LogEvent("helper_refresh", fields)
}

// ensureTunAfterProtectOn is the Protect On lifecycle hook for T1+.
// Default: log tun_start_skipped (T0 nft path). With DENYOUT_TUN_E2E=1 or
// TunDataplane pref, request real denyout0; on failure fall back to T0 UDP drop.
func (a *App) ensureTunAfterProtectOn(uid int) {
	fields := map[string]any{
		"uid":   uid,
		"phase": string(tun.ActivePhase()),
	}
	if !a.tunGateOn() {
		fields["reason"] = "flag_off"
		LogEvent("tun_start_skipped", fields)
		return
	}
	if tun.WantDevice() {
		fields["env"] = tun.EnvE2E
	} else {
		fields["pref"] = "tun_dataplane"
	}
	line, err := hostguard.HelperTunCallReal("tun-start", uid)
	if err != nil {
		fields["err"] = err.Error()
		LogEvent("tun_start", fields)
		return
	}
	fields["reply"] = line
	if st, perr := tun.ParseHelperReply(line); perr == nil {
		fields["enabled"] = st.Enabled
		if !st.Enabled {
			fields["reason"] = st.Reason
		}
	}
	LogEvent("tun_start", fields)
}

// ensureTunStopped is the Protect Off lifecycle hook for T1+.
func ensureTunStopped(uid int) {
	line, err := hostguard.HelperTunCallReal("tun-stop", uid)
	fields := map[string]any{"uid": uid}
	if err != nil {
		line2, err2 := hostguard.HelperTunCall("tun-stop", uid)
		if err2 != nil {
			fields["err"] = err.Error()
			LogEvent("tun_stop", fields)
			return
		}
		line = line2
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
