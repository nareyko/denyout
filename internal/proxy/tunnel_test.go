package proxy

import (
	"io"
	"net"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	return c, r.c
}

func TestRelayBidirectionalFullExchange(t *testing.T) {
	a, b := tcpPair(t)
	c, d := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- relayBidirectional(b, c) }()

	go func() {
		_, _ = a.Write([]byte("ping"))
		_ = a.(*net.TCPConn).CloseWrite()
	}()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(d, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("%q", buf)
	}
	if _, err := d.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	_ = d.(*net.TCPConn).CloseWrite()
	buf2 := make([]byte, 4)
	if _, err := io.ReadFull(a, buf2); err != nil {
		t.Fatal(err)
	}
	if string(buf2) != "pong" {
		t.Fatalf("%q", buf2)
	}
	_ = a.Close()
	_ = d.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not finish waiting for both sides")
	}
}

// Old bug: returning after the first Copy finished would Close both conns and
// RST the peer before the reverse direction drained.
func TestRelayBidirectionalDoesNotDropReplyAfterClientFIN(t *testing.T) {
	client, cside := tcpPair(t)
	sside, server := tcpPair(t)
	done := make(chan error, 1)
	go func() { done <- relayBidirectional(cside, sside) }()

	if _, err := client.Write([]byte("req")); err != nil {
		t.Fatal(err)
	}
	req := make([]byte, 3)
	if _, err := io.ReadFull(server, req); err != nil {
		t.Fatal(err)
	}
	_ = client.(*net.TCPConn).CloseWrite()
	time.Sleep(20 * time.Millisecond)
	if _, err := server.Write([]byte("res")); err != nil {
		t.Fatal(err)
	}
	_ = server.(*net.TCPConn).CloseWrite()

	res := make([]byte, 3)
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, res); err != nil {
		t.Fatalf("response dropped after client FIN: %v", err)
	}
	if string(res) != "res" {
		t.Fatalf("%q", res)
	}
	_ = client.Close()
	_ = server.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}
