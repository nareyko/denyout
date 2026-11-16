//go:build linux

package tun

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestParseBuildIPv4UDPRoundTrip(t *testing.T) {
	src := &net.UDPAddr{IP: net.IPv4(198, 18, 0, 1), Port: 12345}
	dst := &net.UDPAddr{IP: net.IPv4(198, 18, 0, 10), Port: 443}
	payload := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x16, 0x03, 0x01}
	pkt := buildIPv4UDP(src, dst, payload)
	gotSrc, gotDst, gotPayload, ok := parseIPv4UDP(pkt)
	if !ok {
		t.Fatalf("parse failed on %x", pkt)
	}
	if gotSrc.Port != src.Port || gotDst.Port != dst.Port {
		t.Fatalf("ports src=%v dst=%v", gotSrc, gotDst)
	}
	if gotDst.IP.String() != "198.18.0.10" {
		t.Fatalf("dst ip %v", gotDst.IP)
	}
	if string(gotPayload) != string(payload) {
		t.Fatalf("payload %x vs %x", gotPayload, payload)
	}
}

func TestFixIPv4TransportChecksumTCP(t *testing.T) {
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1000}
	dst := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 443}
	pkt := buildIPv4UDP(src, dst, []byte{1, 2, 3, 4})
	pkt[9] = 6 // TCP
	pkt[10], pkt[11] = 0, 0
	ihl := int(pkt[0]&0x0f) * 4
	pkt[ihl+6], pkt[ihl+7] = 0, 0
	fixed := fixIPv4TransportChecksum(pkt)
	if fixed[10] == 0 && fixed[11] == 0 {
		t.Fatal("ipv4 checksum still zero")
	}
}

func TestHelperLineRealMITM(t *testing.T) {
	line, err := HelperLineRealMITM("tun-start", 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"tun-start", "1000", "real", "mitm"} {
		if !strings.Contains(line, p) {
			t.Fatalf("missing %q in %q", p, line)
		}
	}
	line2, err := HelperLineReal("tun-stats", 42)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"tun-stats", "42", "real"} {
		if !strings.Contains(line2, p) {
			t.Fatalf("missing %q in %q", p, line2)
		}
	}
}

func TestCursorQUICPassthroughDecide(t *testing.T) {
	sni := []byte("api.cursor.sh")
	ext := []byte{
		0x00, 0x00,
		0x00, byte(5 + len(sni)),
		0x00, byte(3 + len(sni)),
		0x00,
		byte(len(sni) >> 8), byte(len(sni)),
	}
	ext = append(ext, sni...)
	body := make([]byte, 0, 64+len(ext))
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x00, 0x2f)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	pkt := append([]byte{0xc0, 0x00, 0x00, 0x00, 0x01}, rec...)

	insp := DefaultQUICInspector{MITM: true}
	dec := insp.Decide(context.TODO(), pkt)
	if dec.SNI != "api.cursor.sh" {
		t.Fatalf("sni=%q %+v", dec.SNI, dec)
	}
	if dec.Action != QUICActionDrop || dec.Reason != "cursor_passthrough_no_quic_mitm" {
		t.Fatalf("%+v", dec)
	}
}
