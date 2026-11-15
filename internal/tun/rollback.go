package tun

import "fmt"

// RollbackStep is one operator/helper action to leave T1 and restore T0 Protect.
type RollbackStep struct {
	ID   string
	Cmd  string
	Note string
}

// RollbackPlan is the closed-loop restore sequence (string contract; not executed here).
func RollbackPlan() []RollbackStep {
	return []RollbackStep{
		{ID: "tun-stop", Cmd: "tun-stop 0 $UID -", Note: "helper verb; stub until real device"},
		{ID: "link-del", Cmd: "ip link delete " + DeviceName, Note: "ignore missing device"},
		{ID: "t0-apply", Cmd: "hostctl apply --port $PORT --uid $UID --ca $CA", Note: "restore nft denyout-block-quic"},
	}
}

// FormatRollbackPlan prints steps for docs/hostctl help.
func FormatRollbackPlan() string {
	var out string
	for i, s := range RollbackPlan() {
		out += fmt.Sprintf("%d. [%s] %s  # %s\n", i+1, s.ID, s.Cmd, s.Note)
	}
	return out
}
