package tun_test

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/tun"
)

func TestFormatParseDropStatsRoundTrip(t *testing.T) {
	in := tun.DropStats{Packets: 7, Bytes: 99, Present: true, Source: tun.SourceTUN}
	line := "OK tun1 " + tun.FormatDropStatsLine(in)
	out, err := tun.ParseDropStatsLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("got %+v want %+v", out, in)
	}
}

func TestParseDropStatsLegacyNFTNoSource(t *testing.T) {
	st, err := tun.ParseDropStatsLine("OK quic1 packets=3 bytes=10 present=true")
	if err != nil {
		t.Fatal(err)
	}
	if st.Packets != 3 || st.Bytes != 10 || !st.Present || st.Source != tun.SourceNFT {
		t.Fatalf("%+v", st)
	}
}

func TestParseDropStatsReject(t *testing.T) {
	if _, err := tun.ParseDropStatsLine("ERR no"); err == nil {
		t.Fatal("expected error")
	}
}

func TestCounterRecord(t *testing.T) {
	c := tun.NewCounter()
	c.Record(100)
	c.Record(50)
	st := c.Snapshot()
	if st.Packets != 2 || st.Bytes != 150 {
		t.Fatalf("%+v", st)
	}
	if !strings.Contains(tun.FormatDropStatsLine(st), "source=tun") {
		t.Fatal(tun.FormatDropStatsLine(st))
	}
}
