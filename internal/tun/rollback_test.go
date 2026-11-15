package tun_test

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/tun"
)

func TestRollbackPlan(t *testing.T) {
	steps := tun.RollbackPlan()
	if len(steps) < 3 {
		t.Fatalf("steps=%d", len(steps))
	}
	if steps[0].ID != "tun-stop" || !strings.Contains(steps[1].Cmd, tun.DeviceName) {
		t.Fatalf("%+v", steps)
	}
	txt := tun.FormatRollbackPlan()
	if !strings.Contains(txt, "denyout-block-quic") && !strings.Contains(txt, "hostctl apply") {
		t.Fatalf("%q", txt)
	}
	// Must stay documentation-only (matches package RollbackHint).
	if !strings.Contains(tun.RollbackHint(), "tun-stop") {
		t.Fatal(tun.RollbackHint())
	}
}
