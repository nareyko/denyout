package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrShortPacket is returned when the buffer cannot hold IP+UDP headers.
var ErrShortPacket = errors.New("tun: short packet")

// ErrNotUDP is returned when the L4 protocol is not UDP.
var ErrNotUDP = errors.New("tun: not udp")

// ErrUnsupportedIP is returned for non-IPv4/IPv6 version fields.
var ErrUnsupportedIP = errors.New("tun: unsupported ip version")

// Classified is an L3/L4 view parsed from a raw IP packet (no kernel I/O).
type Classified struct {
	Packet
	IPVersion int
	PayloadN  int // UDP payload length (excludes UDP header)
	TotalN    int // full IP packet length from header (or len(buf) if truncated)
}

// ClassifyIPPacket parses IPv4/IPv6 + UDP headers for T1 decisions.
// mark/uid are supplied by the capture path (nft/tproxy), not from the packet.
func ClassifyIPPacket(buf []byte, mark uint32, uid int) (Classified, error) {
	var out Classified
	out.Mark = mark
	out.UID = uid
	if len(buf) < 1 {
		return out, ErrShortPacket
	}
	ver := int(buf[0] >> 4)
	out.IPVersion = ver
	switch ver {
	case 4:
		return classifyIPv4UDP(buf, out)
	case 6:
		return classifyIPv6UDP(buf, out)
	default:
		return out, fmt.Errorf("%w: %d", ErrUnsupportedIP, ver)
	}
}

func classifyIPv4UDP(buf []byte, out Classified) (Classified, error) {
	if len(buf) < 20 {
		return out, ErrShortPacket
	}
	ihl := int(buf[0]&0x0f) * 4
	if ihl < 20 || len(buf) < ihl+8 {
		return out, ErrShortPacket
	}
	total := int(binary.BigEndian.Uint16(buf[2:4]))
	if total < ihl+8 {
		return out, ErrShortPacket
	}
	if buf[9] != 17 { // IPPROTO_UDP
		out.Proto = protoName(buf[9])
		return out, ErrNotUDP
	}
	udp := buf[ihl:]
	out.Proto = "udp"
	out.DstPort = binary.BigEndian.Uint16(udp[2:4])
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 {
		return out, ErrShortPacket
	}
	out.PayloadN = udpLen - 8
	out.TotalN = total
	return out, nil
}

func classifyIPv6UDP(buf []byte, out Classified) (Classified, error) {
	// Fixed IPv6 header; T1 spike ignores extension headers (treat as unsupported).
	if len(buf) < 40+8 {
		return out, ErrShortPacket
	}
	next := buf[6]
	payloadLen := int(binary.BigEndian.Uint16(buf[4:6]))
	if next != 17 {
		out.Proto = protoName(next)
		return out, ErrNotUDP
	}
	udp := buf[40:]
	out.Proto = "udp"
	out.DstPort = binary.BigEndian.Uint16(udp[2:4])
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 {
		return out, ErrShortPacket
	}
	out.PayloadN = udpLen - 8
	out.TotalN = 40 + payloadLen
	return out, nil
}

func protoName(p byte) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("ipproto-%d", p)
	}
}
