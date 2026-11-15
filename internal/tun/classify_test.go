package tun_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/nareyko/denyout/internal/tun"
)

func ipv4UDP(dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	total := 20 + udpLen
	buf := make([]byte, total)
	buf[0] = 0x45 // v4, IHL=5
	binary.BigEndian.PutUint16(buf[2:4], uint16(total))
	buf[9] = 17 // UDP
	// src 10.0.0.1 → dst 1.1.1.1
	copy(buf[12:16], []byte{10, 0, 0, 1})
	copy(buf[16:20], []byte{1, 1, 1, 1})
	udp := buf[20:]
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)
	return buf
}

func ipv4TCP(dstPort uint16) []byte {
	buf := make([]byte, 40)
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], 40)
	buf[9] = 6 // TCP
	tcp := buf[20:]
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	return buf
}

func ipv6UDP(dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	buf := make([]byte, 40+udpLen)
	buf[0] = 0x60 // v6
	binary.BigEndian.PutUint16(buf[4:6], uint16(udpLen))
	buf[6] = 17 // next = UDP
	udp := buf[40:]
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)
	return buf
}

func TestClassifyIPv4UDP443(t *testing.T) {
	buf := ipv4UDP(443, []byte("quic"))
	cl, err := tun.ClassifyIPPacket(buf, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if cl.IPVersion != 4 || cl.Proto != "udp" || cl.DstPort != 443 {
		t.Fatalf("%+v", cl)
	}
	if cl.PayloadN != 4 || cl.TotalN != len(buf) || cl.UID != 1000 {
		t.Fatalf("%+v", cl)
	}
}

func TestClassifyIPv6UDP443(t *testing.T) {
	buf := ipv6UDP(443, []byte("x"))
	cl, err := tun.ClassifyIPPacket(buf, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if cl.IPVersion != 6 || cl.DstPort != 443 || cl.PayloadN != 1 {
		t.Fatalf("%+v", cl)
	}
}

func TestClassifyNotUDP(t *testing.T) {
	_, err := tun.ClassifyIPPacket(ipv4TCP(443), 0, 1)
	if !errors.Is(err, tun.ErrNotUDP) {
		t.Fatalf("err=%v", err)
	}
}

func TestClassifyShort(t *testing.T) {
	_, err := tun.ClassifyIPPacket([]byte{0x45}, 0, 1)
	if !errors.Is(err, tun.ErrShortPacket) {
		t.Fatalf("err=%v", err)
	}
}

func TestClassifyUnsupportedVersion(t *testing.T) {
	_, err := tun.ClassifyIPPacket([]byte{0x00}, 0, 1)
	if !errors.Is(err, tun.ErrUnsupportedIP) {
		t.Fatalf("err=%v", err)
	}
}
