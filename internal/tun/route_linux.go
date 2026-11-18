//go:build linux

package tun

import (
	"context"
	"net"
	"strings"
)

// routeVerdict is what readLoop does with one packet read from denyout0.
type routeVerdict int

const (
	verdictDrop     routeVerdict = iota // count and discard
	verdictNetstack                     // inject into gVisor (TCP / anything else IP when a netstack runs)
	verdictMITMQUIC                     // hand the UDP payload to the QUIC MITM bridge
)

// routeDecision is the pure per-packet decision (no I/O, no counters).
type routeDecision struct {
	verdict routeVerdict
	// sight is set when the QUIC inspector produced a sighting to report.
	sight    bool
	decision QUICDecision
	// Valid for verdictMITMQUIC.
	src, dst *net.UDPAddr
	payload  []byte
}

// routePacket classifies one raw IP packet. hasNS / hasBridge say whether the
// gVisor netstack and the QUIC MITM bridge are running.
//
//   - UDP/443: inspector decides; MITM goes to the bridge when present and the
//     packet parses as IPv4/UDP, everything else is dropped (sighting still reported).
//   - Otherwise with a netstack: anything the classifier rejects (TCP, ICMP, …)
//     but that carries an IPv4/IPv6 version nibble is injected into gVisor.
//   - Everything else is dropped.
func routePacket(pkt []byte, insp DefaultQUICInspector, hasNS, hasBridge bool) routeDecision {
	cl, cerr := ClassifyIPPacket(pkt, SteerMark, 0)
	if cerr == nil && strings.EqualFold(cl.Proto, "udp") && cl.DstPort == 443 {
		return routeQUIC(pkt, insp, hasBridge)
	}
	if hasNS && cerr != nil && isIPVersion(pkt) {
		return routeDecision{verdict: verdictNetstack}
	}
	return routeDecision{verdict: verdictDrop}
}

func routeQUIC(pkt []byte, insp DefaultQUICInspector, hasBridge bool) routeDecision {
	src, dst, payload, pok := parseIPv4UDP(pkt)
	decideBuf := pkt
	if pok {
		decideBuf = payload
	}
	dec := insp.Decide(context.TODO(), decideBuf)
	out := routeDecision{
		verdict:  verdictDrop,
		sight:    dec.Action == QUICActionSight || dec.Action == QUICActionMITM || dec.HasSNI(),
		decision: dec,
	}
	if dec.Action == QUICActionMITM && hasBridge && pok {
		out.verdict = verdictMITMQUIC
		out.src, out.dst, out.payload = src, dst, payload
	}
	return out
}

func isIPVersion(pkt []byte) bool {
	if len(pkt) == 0 {
		return false
	}
	v := pkt[0] >> 4
	return v == 4 || v == 6
}
