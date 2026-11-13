//go:build linux

package proxy

import (
	"net"
	"syscall"
	"unsafe"
)

func originalDst(conn net.Conn) (string, int) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		// prefixConn unwrap
		if pc, ok := conn.(*prefixConn); ok {
			tc, _ = pc.Conn.(*net.TCPConn)
		}
	}
	if tc == nil {
		return "", 0
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return "", 0
	}
	var addr syscall.RawSockaddrInet4
	var err2 error
	cerr := rc.Control(func(fd uintptr) {
		const soOriginalDst = 80
		const solIP = syscall.SOL_IP
		size := uint32(unsafe.Sizeof(addr))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(solIP),
			uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			err2 = errno
		}
	})
	if cerr != nil || err2 != nil {
		return "", 0
	}
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(addr.Port>>8 | addr.Port<<8)
	if ip.IsLoopback() || ip.IsUnspecified() {
		return "", 0
	}
	return ip.String(), port
}
