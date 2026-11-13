//go:build !linux

package proxy

import (
	"net"
	"time"
)

func (s *Server) dialTCP(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, timeout)
}
