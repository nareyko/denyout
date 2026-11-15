package tun_test

import (
	"testing"

	"github.com/nareyko/denyout/internal/tun"
)

func TestEngineBatchQUICDrops(t *testing.T) {
	e := tun.NewEngine()
	var wantBytes uint64
	for i := 0; i < 5; i++ {
		buf := ipv4UDP(443, []byte("quic-payload"))
		act, cl, err := e.Handle(buf, 0, 1000)
		if err != nil || act != tun.ActionDropLog {
			t.Fatalf("i=%d act=%s err=%v", i, act, err)
		}
		wantBytes += uint64(cl.TotalN)
	}
	// Marked packet must not count.
	_, _, _ = e.Handle(ipv4UDP(443, []byte("x")), tun.DenyOutMark, 1000)
	// DNS must not count.
	_, _, _ = e.Handle(ipv4UDP(53, []byte("dns")), 0, 1000)

	st := e.Drops.Snapshot()
	if st.Packets != 5 || st.Bytes != wantBytes || st.Source != tun.SourceTUN {
		t.Fatalf("%+v want packets=5 bytes=%d", st, wantBytes)
	}
	line := "OK tun1 " + tun.FormatDropStatsLine(st)
	parsed, err := tun.ParseDropStatsLine(line)
	if err != nil || parsed != st {
		t.Fatalf("parse %+v err=%v", parsed, err)
	}
}
