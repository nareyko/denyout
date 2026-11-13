//go:build linux

package proxy

import (
	"net"
	"syscall"
	"time"
)

// Packet mark so nft hostguard can skip DenyOut's own upstream dials (avoid redirect loops).
const divertMark = 0x646e79 // 'dny'

func (s *Server) dialTCP(addr string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	if s.cfg.Transparent {
		d.Control = func(network, address string, c syscall.RawConn) error {
			var err error
			cerr := c.Control(func(fd uintptr) {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, divertMark)
			})
			if cerr != nil {
				return cerr
			}
			return err
		}
	}
	return d.Dial("tcp", addr)
}
