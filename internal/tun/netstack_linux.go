//go:build linux

package tun

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TCPHandler receives accepted TCP connections from the gVisor stack (T3).
// dstHost/dstPort are the original destination when known.
type TCPHandler func(conn net.Conn, dstIP net.IP, dstPort uint16)

// Netstack bridges a TUN reader/writer to gVisor and accepts TCP.
type Netstack struct {
	stack   *stack.Stack
	ep      *channel.Endpoint
	handler TCPHandler
	stop    chan struct{}
}

// NewNetstack builds an IPv4/IPv6 stack with TCP/UDP and a channel NIC.
func NewNetstack(handler TCPHandler) (*Netstack, error) {
	if handler == nil {
		handler = func(c net.Conn, _ net.IP, _ uint16) { _ = c.Close() }
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	const nicID = 1
	ep := channel.New(1024, uint32(1500), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("tun netstack nic: %v", err)
	}
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	_, _ = s.SetNICForwarding(nicID, ipv4.ProtocolNumber, true)
	_, _ = s.SetNICForwarding(nicID, ipv6.ProtocolNumber, true)
	// Only the TUN endpoint address is local. Destinations like lab IPs stay
	// non-local so tcp.Forwarder (not a missing listener RST) handles SYNs.
	s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{198, 18, 0, 1}),
			PrefixLen: 32,
		},
	}, stack.AddressProperties{})
	sack := tcpip.TCPSACKEnabled(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	ns := &Netstack{stack: s, ep: ep, handler: handler, stop: make(chan struct{})}
	tcpFwd := tcp.NewForwarder(s, 0, 1024, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		go func() {
			// Run outside the stack's packet-dispatch goroutine so CreateEndpoint
			// can emit SYN-ACK via ReadOutbound without self-deadlocking.
			var wq waiter.Queue
			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				r.Complete(true)
				return
			}
			r.Complete(false)
			conn := gonet.NewTCPConn(&wq, ep)
			ip := append(net.IP(nil), id.LocalAddress.AsSlice()...)
			ns.handler(conn, ip, id.LocalPort)
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	return ns, nil
}

// InjectInbound delivers one IP packet from the TUN into gVisor.
func (ns *Netstack) InjectInbound(pkt []byte) {
	if ns == nil || ns.ep == nil || len(pkt) < 1 {
		return
	}
	var proto tcpip.NetworkProtocolNumber
	switch pkt[0] >> 4 {
	case 4:
		proto = ipv4.ProtocolNumber
		pkt = fixIPv4TransportChecksum(pkt)
	case 6:
		proto = ipv6.ProtocolNumber
	default:
		return
	}
	view := buffer.MakeWithData(append([]byte(nil), pkt...))
	ns.ep.InjectInbound(proto, stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: view}))
}

// fixIPv4TransportChecksum recomputes IPv4/TCP/UDP checksums. Packets steered
// into TUN often arrive with offloaded (zero/partial) L4 checksums that gVisor rejects.
func fixIPv4TransportChecksum(pkt []byte) []byte {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return pkt
	}
	out := append([]byte(nil), pkt...)
	ihl := int(out[0]&0x0f) * 4
	if ihl < 20 || len(out) < ihl {
		return out
	}
	binary.BigEndian.PutUint16(out[10:12], 0)
	binary.BigEndian.PutUint16(out[10:12], ipHeaderChecksum(out[:ihl]))
	proto := out[9]
	if proto != 6 && proto != 17 {
		return out
	}
	if len(out) < ihl+8 {
		return out
	}
	l4 := out[ihl:]
	src := net.IP(out[12:16])
	dst := net.IP(out[16:20])
	binary.BigEndian.PutUint16(l4[6:8], 0)
	binary.BigEndian.PutUint16(l4[6:8], pseudoHeaderChecksum(src, dst, proto, l4))
	return out
}

func ipHeaderChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	if len(hdr)%2 == 1 {
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func pseudoHeaderChecksum(src, dst net.IP, proto byte, l4 []byte) uint16 {
	s4, d4 := src.To4(), dst.To4()
	if s4 == nil || d4 == nil {
		return 0
	}
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(s4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(s4[2:4]))
	sum += uint32(binary.BigEndian.Uint16(d4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(d4[2:4]))
	sum += uint32(proto)
	sum += uint32(len(l4))
	for i := 0; i+1 < len(l4); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(l4[i : i+2]))
	}
	if len(l4)%2 == 1 {
		sum += uint32(l4[len(l4)-1]) << 8
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

type channelNotify struct {
	ch chan struct{}
}

func (n *channelNotify) WriteNotify() {
	select {
	case n.ch <- struct{}{}:
	default:
	}
}

// ReadOutbound copies packets gVisor wants to send back to the TUN writer.
func (ns *Netstack) ReadOutbound(w io.Writer) error {
	n := &channelNotify{ch: make(chan struct{}, 1)}
	h := ns.ep.AddNotify(n)
	defer ns.ep.RemoveNotify(h)
	for {
		for {
			pkt := ns.ep.Read()
			if pkt == nil {
				break
			}
			v := pkt.ToView()
			_, err := w.Write(v.AsSlice())
			pkt.DecRef()
			if err != nil {
				return err
			}
		}
		select {
		case <-ns.stop:
			return nil
		case <-n.ch:
		}
	}
}

// Close stops the stack.
func (ns *Netstack) Close() {
	select {
	case <-ns.stop:
	default:
		close(ns.stop)
	}
	if ns.stack != nil {
		ns.stack.Close()
	}
}
