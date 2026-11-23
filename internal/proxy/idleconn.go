package proxy

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Idle limits for intercepted connections. A rolling per-operation deadline bounds how
// long a stalled peer can hold a connection and its goroutines; it is not a cap on the
// total transfer time (a long upload or stream keeps going while bytes flow).
var (
	// clientRequestIdle: waiting for the next request line + headers on a keep-alive connection.
	clientRequestIdle = 5 * time.Minute
	// clientBodyIdle: once a request started, the client must keep sending its body and
	// reading the response.
	clientBodyIdle = 60 * time.Second
	// upstreamIdle: waiting for the upstream's response or its next bytes. Generous on
	// purpose: a non-streaming model call may take minutes before the first byte.
	upstreamIdle = 10 * time.Minute
)

// idleConn re-arms the read/write deadline before every Read and Write. Explicit
// deadlines set by callers (handshake bound, drain bound) still apply: the earlier of the
// two wins, and clearing one (zero time) leaves only the idle limit.
type idleConn struct {
	net.Conn
	mu         sync.Mutex
	idle       time.Duration
	rcap, wcap time.Time
}

func newIdleConn(c net.Conn, idle time.Duration) *idleConn { return &idleConn{Conn: c, idle: idle} }

// SetIdle changes the per-operation idle limit.
func (c *idleConn) SetIdle(d time.Duration) {
	c.mu.Lock()
	c.idle = d
	c.mu.Unlock()
}

func (c *idleConn) next(limit time.Time) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := time.Now().Add(c.idle)
	if !limit.IsZero() && limit.Before(d) {
		d = limit
	}
	return d
}

func (c *idleConn) rlimit() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.rcap }
func (c *idleConn) wlimit() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.wcap }

func (c *idleConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(c.next(c.rlimit()))
	return c.Conn.Read(p)
}

func (c *idleConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(c.next(c.wlimit()))
	return c.Conn.Write(p)
}

func (c *idleConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rcap = t
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *idleConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wcap = t
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

func (c *idleConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.rcap, c.wcap = t, t
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

// writeSimple sends a complete plain-text response that tells the client the connection
// is closing (callers must then close it).
func writeSimple(w io.Writer, status int, body string) {
	resp := &http.Response{
		StatusCode:    status,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp.Header.Set("Connection", "close")
	_ = resp.Write(w)
}
