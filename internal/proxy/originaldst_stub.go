//go:build !linux

package proxy

import "net"

func originalDst(conn net.Conn) (string, int) {
	_ = conn
	return "", 0
}
