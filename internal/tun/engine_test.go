package tun_test

import (
	"testing"

	"github.com/nareyko/denyout/internal/tun"
)

func TestEngineDropLogCounts(t *testing.T) {
	e := tun.NewEngine()
	buf := ipv4UDP(443, []byte("abcd"))
	act, cl, err := e.Handle(buf, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if act != tun.ActionDropLog {
		t.Fatalf("act=%s", act)
	}
	st := e.Drops.Snapshot()
	if st.Packets != 1 || st.Bytes != uint64(cl.TotalN) || st.Source != tun.SourceTUN {
		t.Fatalf("%+v", st)
	}
}

func TestEngineSkipMarkedNoCount(t *testing.T) {
	e := tun.NewEngine()
	act, _, err := e.Handle(ipv4UDP(443, nil), tun.DenyOutMark, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if act != tun.ActionSkip {
		t.Fatalf("act=%s", act)
	}
	if e.Drops.Snapshot().Packets != 0 {
		t.Fatal("marked traffic must not increment drop counter")
	}
}

func TestEngineOtherUDPDirectNoCount(t *testing.T) {
	e := tun.NewEngine()
	act, _, err := e.Handle(ipv4UDP(53, []byte("dns")), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if act != tun.ActionDirect {
		t.Fatalf("act=%s", act)
	}
	if e.Drops.Snapshot().Packets != 0 {
		t.Fatal("non-443 UDP must not count as QUIC drop")
	}
}

func TestEngineTCPUnsupported(t *testing.T) {
	e := tun.NewEngine()
	act, _, err := e.Handle(ipv4TCP(443), 0, 1000)
	if err == nil {
		t.Fatal("expected not-udp error")
	}
	if act != tun.ActionUnsupported {
		t.Fatalf("act=%s", act)
	}
}
