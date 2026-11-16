//go:build !linux

package tun

import (
	"fmt"
	"io"
	"net"
)

// TCPHandler receives accepted TCP connections (stub off Linux).
type TCPHandler func(conn net.Conn, dstIP net.IP, dstPort uint16)

// Netstack is unavailable off Linux.
type Netstack struct{}

// NewNetstack returns an error off Linux.
func NewNetstack(handler TCPHandler) (*Netstack, error) {
	_ = handler
	return nil, fmt.Errorf("tun: gVisor netstack only on Linux")
}

// InjectInbound is a no-op stub.
func (ns *Netstack) InjectInbound(pkt []byte) { _ = pkt }

// ReadOutbound is a no-op stub.
func (ns *Netstack) ReadOutbound(w io.Writer) error {
	_ = w
	return fmt.Errorf("tun: netstack unavailable")
}

// Close is a no-op stub.
func (ns *Netstack) Close() {}
