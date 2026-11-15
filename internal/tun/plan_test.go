package tun_test

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/tun"
)

func TestDecideT1QUICDrop(t *testing.T) {
	a := tun.DecideT1(tun.Packet{Proto: "udp", DstPort: 443, UID: 1000})
	if a != tun.ActionDropLog {
		t.Fatalf("got %s", a)
	}
}

func TestDecideT1SkipMarked(t *testing.T) {
	a := tun.DecideT1(tun.Packet{Proto: "udp", DstPort: 443, Mark: tun.DenyOutMark})
	if a != tun.ActionSkip {
		t.Fatalf("got %s", a)
	}
}

func TestDecideT1OtherUDPDirect(t *testing.T) {
	a := tun.DecideT1(tun.Packet{Proto: "udp", DstPort: 53})
	if a != tun.ActionDirect {
		t.Fatalf("got %s", a)
	}
}

func TestDecideT1TCPUnsupportedInT1(t *testing.T) {
	a := tun.DecideT1(tun.Packet{Proto: "tcp", DstPort: 443})
	if a != tun.ActionUnsupported {
		t.Fatalf("got %s", a)
	}
}

func TestEnabledForPhase(t *testing.T) {
	if tun.EnabledForPhase(tun.PhaseT0NFTOnly) {
		t.Fatal("T0 must not create TUN")
	}
	if !tun.EnabledForPhase(tun.PhaseT1UDP443) {
		t.Fatal("T1 would enable TUN device in a future build")
	}
}

func TestHelperLine(t *testing.T) {
	line, err := tun.HelperLine("tun-stats", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "tun-stats 0 1000") {
		t.Fatalf("line=%q", line)
	}
	if _, err := tun.HelperLine("apply", 1); err == nil {
		t.Fatal("expected error for unknown verb")
	}
}

// Guard: this package must stay importable in CI without CAP_NET_ADMIN.
func TestNoKernelSideEffectsOnImport(t *testing.T) {
	_ = tun.DecideT1(tun.Packet{Proto: "udp", DstPort: 443})
}
