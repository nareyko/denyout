//go:build linux

package tun

import "testing"

func TestRoutePacketTable(t *testing.T) {
	udp443 := tIPv4(17, 4000, 443, []byte("initial"))
	cases := []struct {
		name      string
		pkt       []byte
		insp      DefaultQUICInspector
		ns, brdg  bool
		verdict   routeVerdict
		wantSight bool
	}{
		{"udp443 plain -> drop", udp443, DefaultQUICInspector{}, false, false, verdictDrop, false},
		{"udp443 mitm with bridge", udp443, DefaultQUICInspector{MITM: true}, false, true, verdictMITMQUIC, true},
		{"udp443 mitm without bridge", udp443, DefaultQUICInspector{MITM: true}, false, false, verdictDrop, true},
		{"udp443 mitm ns only", udp443, DefaultQUICInspector{MITM: true}, true, false, verdictDrop, true},
		{"udp53 no ns", tIPv4(17, 1, 53, []byte("d")), DefaultQUICInspector{}, false, false, verdictDrop, false},
		{"udp53 with ns", tIPv4(17, 1, 53, []byte("d")), DefaultQUICInspector{}, true, false, verdictDrop, false},
		{"tcp no ns", tIPv4(6, 1, 443, nil), DefaultQUICInspector{}, false, false, verdictDrop, false},
		{"tcp ns", tIPv4(6, 1, 443, nil), DefaultQUICInspector{}, true, false, verdictNetstack, false},
		{"icmp ns", tIPv4(1, 0, 0, nil), DefaultQUICInspector{}, true, false, verdictNetstack, false},
		{"v6 udp443 drop", tIPv6UDP(443, []byte("x")), DefaultQUICInspector{}, true, false, verdictDrop, false},
		{"truncated v4 with ns", []byte{0x45, 0, 0}, DefaultQUICInspector{}, true, false, verdictNetstack, false},
		{"truncated v6 with ns", []byte{0x60, 0}, DefaultQUICInspector{}, true, false, verdictNetstack, false},
		{"bad version ns", []byte{0x20, 0, 0}, DefaultQUICInspector{}, true, false, verdictDrop, false},
		{"empty", nil, DefaultQUICInspector{}, true, true, verdictDrop, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rd := routePacket(c.pkt, c.insp, c.ns, c.brdg)
			if rd.verdict != c.verdict || rd.sight != c.wantSight {
				t.Fatalf("verdict=%d sight=%v want %d/%v", rd.verdict, rd.sight, c.verdict, c.wantSight)
			}
			if rd.verdict == verdictMITMQUIC && (string(rd.payload) != "initial" || rd.src.Port != 4000 || rd.dst.Port != 443) {
				t.Fatalf("bridge fields: %+v", rd)
			}
		})
	}
}

func TestRoutePacketSNISightingOnDrop(t *testing.T) {
	// A decision carrying an SNI is reported even when the action is drop.
	rd := routeQUIC(tIPv4(17, 1, 443, []byte("x")), DefaultQUICInspector{}, false)
	if rd.sight {
		t.Fatal("no SNI -> no sight")
	}
	if !(QUICDecision{SNI: " a.com "}).HasSNI() || (QUICDecision{SNI: "  "}).HasSNI() {
		t.Fatal("HasSNI")
	}
}
