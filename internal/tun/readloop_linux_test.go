//go:build linux

package tun

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// fakeDev feeds a fixed list of packets to readLoop, then fails the next Read
// so the loop returns.
type fakeDev struct {
	pkts   [][]byte
	closed bool
}

func (f *fakeDev) File() *os.File                   { return nil }
func (f *fakeDev) MTU() (int, error)                { return 1500, nil }
func (f *fakeDev) Name() (string, error)            { return DeviceName, nil }
func (f *fakeDev) Events() <-chan wgtun.Event       { return nil }
func (f *fakeDev) BatchSize() int                   { return 1 }
func (f *fakeDev) Write([][]byte, int) (int, error) { return 0, nil }
func (f *fakeDev) Close() error                     { f.closed = true; return nil }
func (f *fakeDev) Read(bufs [][]byte, sizes []int, _ int) (int, error) {
	if len(f.pkts) == 0 {
		return 0, os.ErrClosed
	}
	p := f.pkts[0]
	f.pkts = f.pkts[1:]
	sizes[0] = copy(bufs[0], p)
	return 1, nil
}

func tIPv4(proto byte, srcPort, dstPort uint16, payload []byte) []byte {
	l4 := 8 + len(payload)
	if proto == 6 {
		l4 = 20 + len(payload)
	}
	buf := make([]byte, 20+l4)
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[9] = proto
	copy(buf[12:16], []byte{10, 0, 0, 1})
	copy(buf[16:20], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(buf[20:22], srcPort)
	binary.BigEndian.PutUint16(buf[22:24], dstPort)
	if proto == 17 {
		binary.BigEndian.PutUint16(buf[24:26], uint16(l4))
		copy(buf[28:], payload)
	}
	return buf
}

func tIPv6UDP(dstPort uint16, payload []byte) []byte {
	buf := make([]byte, 40+8+len(payload))
	buf[0] = 0x60
	binary.BigEndian.PutUint16(buf[4:6], uint16(8+len(payload)))
	buf[6] = 17
	binary.BigEndian.PutUint16(buf[42:44], dstPort)
	binary.BigEndian.PutUint16(buf[44:46], uint16(8+len(payload)))
	copy(buf[48:], payload)
	return buf
}

func runReadLoop(t *testing.T, pkts [][]byte, ns *Netstack, insp DefaultQUICInspector, bridge *quicTUNPacketConn) (r *Runtime, sights []QUICDecision) {
	t.Helper()
	r = &Runtime{}
	dev := &fakeDev{pkts: pkts}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		readLoop(dev, r, ns, insp, func(d QUICDecision) { sights = append(sights, d) }, bridge, done)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("readLoop did not return")
	}
	if !dev.closed {
		t.Fatal("readLoop must close the device on exit")
	}
	return r, sights
}

func TestReadLoopDropsNonSteered(t *testing.T) {
	pkts := [][]byte{
		tIPv4(17, 1000, 53, []byte("dns")),       // UDP other port -> drop
		tIPv4(6, 1000, 443, nil),                 // TCP without netstack -> drop
		tIPv4(17, 1000, 443, []byte("not-quic")), // UDP/443 non-QUIC -> drop
		tIPv6UDP(443, []byte("x")),               // v6 UDP/443 -> drop
		{0x20, 0, 0},                             // junk version -> drop
	}
	r, sights := runReadLoop(t, pkts, nil, DefaultQUICInspector{}, nil)
	if got := r.packets.Load(); got != uint64(len(pkts)) {
		t.Fatalf("dropped %d want %d", got, len(pkts))
	}
	var want uint64
	for _, p := range pkts {
		want += uint64(len(p))
	}
	if r.bytes.Load() != want {
		t.Fatalf("bytes %d want %d", r.bytes.Load(), want)
	}
	// non-QUIC UDP/443 payload: Drop, no SNI -> no sight callback
	if len(sights) != 0 {
		t.Fatalf("sights %v", sights)
	}
}

func TestReadLoopNetstackInjectsTCPAndV6NotDrop(t *testing.T) {
	ns, err := NewNetstack(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	pkts := [][]byte{
		tIPv4(6, 1000, 443, nil),              // tcp -> injected
		tIPv4(1, 0, 0, nil),                   // icmp (ipproto-1) v4 -> injected
		tIPv6UDP(53, []byte("x")),             // v6 non-443 UDP -> classify ok, udp, not 443 -> drop
		{0x20, 0, 0},                          // junk -> drop
		tIPv4(17, 1000, 53, []byte("dns")),    // udp other port -> drop
		tIPv4(17, 1000, 443, []byte("not-q")), // udp/443 -> drop
	}
	r, _ := runReadLoop(t, pkts, ns, DefaultQUICInspector{}, nil)
	if got := r.packets.Load(); got != 4 {
		t.Fatalf("dropped %d want 4", got)
	}
}

func TestReadLoopMITMBridge(t *testing.T) {
	bridge := newQUICTUNPacketConn(func(dst, src *net.UDPAddr, payload []byte) error { return nil })
	pkt := tIPv4(17, 4242, 443, []byte("initial"))
	r, sights := runReadLoop(t, [][]byte{pkt}, nil, DefaultQUICInspector{MITM: true}, bridge)
	if r.packets.Load() != 0 {
		t.Fatal("bridged packet must not count as drop")
	}
	if len(sights) != 1 || sights[0].Action != QUICActionMITM {
		t.Fatalf("sights %+v", sights)
	}
	select {
	case d := <-bridge.in:
		if string(d.payload) != "initial" || d.from.Port != 4242 || d.to.Port != 443 || !d.to.IP.Equal(net.IPv4(1, 1, 1, 1)) {
			t.Fatalf("datagram %+v", d)
		}
	default:
		t.Fatal("nothing pushed to bridge")
	}
	// MITM decision but no bridge: dropped, still sighted.
	r, sights = runReadLoop(t, [][]byte{pkt}, nil, DefaultQUICInspector{MITM: true}, nil)
	if r.packets.Load() != 1 || len(sights) != 1 {
		t.Fatalf("drops=%d sights=%d", r.packets.Load(), len(sights))
	}
}
