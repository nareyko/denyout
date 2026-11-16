//go:build linux

package tun

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// quicDatagram is one UDP payload observed on denyout0 destined to :443.
type quicDatagram struct {
	payload []byte
	from    *net.UDPAddr
	to      *net.UDPAddr // original server (SNI host resolved IP:443)
}

// quicTUNPacketConn presents TUN-captured UDP/443 as a PacketConn for quic-go.
type quicTUNPacketConn struct {
	mu       sync.Mutex
	closed   bool
	in       chan quicDatagram
	write    func(dst *net.UDPAddr, src *net.UDPAddr, payload []byte) error
	local    net.Addr
	replySrc *net.UDPAddr // original server addr (lab:443) for WriteTo spoofing
}

func newQUICTUNPacketConn(write func(dst, src *net.UDPAddr, payload []byte) error) *quicTUNPacketConn {
	return &quicTUNPacketConn{
		in:    make(chan quicDatagram, 64),
		write: write,
		local: &net.UDPAddr{IP: net.IPv4(198, 18, 0, 1), Port: 443},
	}
}

func (c *quicTUNPacketConn) push(d quicDatagram) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if c.replySrc == nil && d.to != nil {
		c.replySrc = &net.UDPAddr{IP: append(net.IP(nil), d.to.IP...), Port: d.to.Port}
		c.local = c.replySrc
	}
	select {
	case c.in <- d:
	default:
		// drop if MITM consumer is slow
	}
}

func (c *quicTUNPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	d, ok := <-c.in
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n := copy(p, d.payload)
	return n, d.from, nil
}

func (c *quicTUNPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("tun: quic WriteTo: want *UDPAddr")
	}
	c.mu.Lock()
	src := c.replySrc
	c.mu.Unlock()
	if src == nil {
		src = &net.UDPAddr{IP: net.IPv4(198, 18, 0, 1), Port: 443}
	}
	if c.write != nil {
		if err := c.write(ua, src, p); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (c *quicTUNPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.in)
	return nil
}

func (c *quicTUNPacketConn) LocalAddr() net.Addr                { return c.local }
func (c *quicTUNPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *quicTUNPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *quicTUNPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// parseIPv4UDP extracts endpoints + payload from a raw IPv4 UDP packet.
func parseIPv4UDP(pkt []byte) (src, dst *net.UDPAddr, payload []byte, ok bool) {
	if len(pkt) < 28 || pkt[0]>>4 != 4 {
		return nil, nil, nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 || pkt[9] != 17 {
		return nil, nil, nil, false
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total > len(pkt) {
		total = len(pkt)
	}
	srcIP := net.IP(append([]byte(nil), pkt[12:16]...))
	dstIP := net.IP(append([]byte(nil), pkt[16:20]...))
	udp := pkt[ihl:total]
	if len(udp) < 8 {
		return nil, nil, nil, false
	}
	sport := int(binary.BigEndian.Uint16(udp[0:2]))
	dport := int(binary.BigEndian.Uint16(udp[2:4]))
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || ihl+udpLen > total {
		udpLen = len(udp)
	}
	payload = append([]byte(nil), udp[8:udpLen]...)
	return &net.UDPAddr{IP: srcIP, Port: sport}, &net.UDPAddr{IP: dstIP, Port: dport}, payload, true
}

// buildIPv4UDP builds a minimal IPv4+UDP packet (checksums left 0; lab/gVisor tolerant).
func buildIPv4UDP(src, dst *net.UDPAddr, payload []byte) []byte {
	ihl := 20
	udpLen := 8 + len(payload)
	total := ihl + udpLen
	buf := make([]byte, total)
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(total))
	buf[8] = 64
	buf[9] = 17
	copy(buf[12:16], src.IP.To4())
	copy(buf[16:20], dst.IP.To4())
	// IPv4 header checksum
	binary.BigEndian.PutUint16(buf[10:12], ipChecksum(buf[:20]))
	udp := buf[20:]
	binary.BigEndian.PutUint16(udp[0:2], uint16(src.Port))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dst.Port))
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(src.IP, dst.IP, udp))
	return buf
}

func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func udpChecksum(src, dst net.IP, udp []byte) uint16 {
	s4, d4 := src.To4(), dst.To4()
	if s4 == nil || d4 == nil {
		return 0
	}
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(s4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(s4[2:4]))
	sum += uint32(binary.BigEndian.Uint16(d4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(d4[2:4]))
	sum += 17
	sum += uint32(len(udp))
	for i := 0; i+1 < len(udp); i += 2 {
		if i == 6 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(udp[i : i+2]))
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	cs := ^uint16(sum)
	if cs == 0 {
		cs = 0xffff
	}
	return cs
}
