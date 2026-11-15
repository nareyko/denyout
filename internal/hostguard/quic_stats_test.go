package hostguard_test

import (
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/hostguard"
)

func TestParseQUICDropCounters(t *testing.T) {
	sample := `
table inet denyout {
  chain output_filter {
    type filter hook output priority filter; policy accept;
    meta mark 0x00646e79 counter packets 1 bytes 60 return
    meta skuid 1000 udp dport 443 counter packets 42 bytes 1337 drop comment "denyout-block-quic"
  }
}
`
	st := hostguard.ParseQUICDropCounters(sample)
	if !st.Present || st.Packets != 42 || st.Bytes != 1337 {
		t.Fatalf("got %+v", st)
	}
	empty := hostguard.ParseQUICDropCounters("table inet denyout {\n}\n")
	if empty.Present || empty.Packets != 0 {
		t.Fatalf("expected empty, got %+v", empty)
	}
	legacy := hostguard.ParseQUICDropCounters(
		`meta skuid 1000 udp dport 443 drop comment "denyout-block-quic"`,
	)
	if !legacy.Present || legacy.Packets != 0 {
		t.Fatalf("legacy rule without counter: %+v", legacy)
	}
}

func TestParseQUICDropStatsLine(t *testing.T) {
	st, err := hostguard.ParseQUICDropStatsLine("OK quic1 packets=9 bytes=100 present=true")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Present || st.Packets != 9 || st.Bytes != 100 || st.Source != "nft" {
		t.Fatalf("got %+v", st)
	}
}

func TestFormatQUICDropStatsRoundTrip(t *testing.T) {
	in := hostguard.QUICDropStats{Packets: 3, Bytes: 99, Present: true, Source: "nft"}
	line := "OK quic1 " + hostguard.FormatQUICDropStatsLine(in)
	if !strings.Contains(line, "source=nft") {
		t.Fatalf("missing source=nft: %q", line)
	}
	out, err := hostguard.ParseQUICDropStatsLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round-trip %+v -> %+v", in, out)
	}
}
