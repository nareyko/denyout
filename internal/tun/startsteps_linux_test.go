//go:build linux

package tun

import (
	"io"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestUndoListRunsNewestFirstAndEmpties(t *testing.T) {
	var u undoList
	var order []int
	for i := 1; i <= 3; i++ {
		i := i
		u.add(func() { order = append(order, i) })
	}
	u.run()
	if !reflect.DeepEqual(order, []int{3, 2, 1}) {
		t.Fatalf("order %v", order)
	}
	u.run() // second run is a no-op
	if len(order) != 3 {
		t.Fatalf("undos ran twice: %v", order)
	}
}

func TestSightingHandlerRecordsAndCallsUser(t *testing.T) {
	r := &Runtime{}
	var got QUICDecision
	h := r.sightingHandler(func(d QUICDecision) { got = d })
	h(QUICDecision{Action: QUICActionSight, SNI: "example.com"})
	if got.SNI != "example.com" {
		t.Fatalf("user not called: %+v", got)
	}
	if st := r.StatsSnapshot(); st.Sightings != 1 || st.LastSNI != "example.com" {
		t.Fatalf("%+v", st)
	}
	// default handler (logging) still records
	r.sightingHandler(nil)(QUICDecision{Action: QUICActionDrop, SNI: ""})
	if st := r.StatsSnapshot(); st.Sightings != 2 || st.LastSNI != "example.com" {
		t.Fatalf("empty SNI must not clear last: %+v", st)
	}
}

func TestNewStopFuncIdempotent(t *testing.T) {
	dev := &fakeDev{}
	done := make(chan struct{})
	mitmCalls := 0
	stop := newStopFunc(done, func() { mitmCalls++ }, nil, nil, dev)
	stop()
	stop() // closing done twice must not panic
	select {
	case <-done:
	default:
		t.Fatal("done not closed")
	}
	if mitmCalls != 2 || !dev.closed {
		t.Fatalf("mitm=%d closed=%v", mitmCalls, dev.closed)
	}
	// nil members are tolerated
	newStopFunc(make(chan struct{}), nil, nil, nil, &fakeDev{})()
}

func TestStartQUICMITMSkipped(t *testing.T) {
	var u undoList
	b, c, err := startQUICMITM(&fakeDev{}, StartOpts{}, false, &u)
	if b != nil || c != nil || err != nil || len(u) != 0 {
		t.Fatal("MITM off must be a no-op")
	}
	// on, but no certificate source: still a no-op
	b, c, err = startQUICMITM(&fakeDev{}, StartOpts{}, true, &u)
	if b != nil || c != nil || err != nil || len(u) != 0 {
		t.Fatal("no GetCertificate must be a no-op")
	}
}

func TestProxyHandoffRelaysAndClosesOnBadPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err == nil {
			_, _ = c.Write([]byte("PONG"))
		}
	}()
	h := proxyHandoff(ln.Addr().(*net.TCPAddr).Port)
	a, b := net.Pipe()
	go h(b, net.IPv4(1, 1, 1, 1), 443)
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := a.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(a, reply); err != nil || string(reply) != "PONG" {
		t.Fatalf("reply %q err=%v", reply, err)
	}
	_ = a.Close()

	// port <= 0: connection is closed immediately
	a2, b2 := net.Pipe()
	go proxyHandoff(0)(b2, nil, 0)
	_ = a2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := a2.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}
