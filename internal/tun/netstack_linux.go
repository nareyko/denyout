//go:build linux

package tun

import (
	"fmt"
	"io"
	"net"
	"sync"

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
	wg      sync.WaitGroup
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
	s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{198, 18, 0, 1}),
			PrefixLen: 16,
		},
	}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	ns := &Netstack{stack: s, ep: ep, handler: handler, stop: make(chan struct{})}
	tcpFwd := tcp.NewForwarder(s, 0, 1024, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		conn := gonet.NewTCPConn(&wq, ep)
		ip := net.IP(id.LocalAddress.AsSlice())
		ns.handler(conn, ip, id.LocalPort)
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
	case 6:
		proto = ipv6.ProtocolNumber
	default:
		return
	}
	view := buffer.MakeWithData(append([]byte(nil), pkt...))
	ns.ep.InjectInbound(proto, stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: view}))
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
