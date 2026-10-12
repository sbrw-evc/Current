package collector

import (
	"syscall"

	"golang.org/x/sys/unix"
)

const reusePortSupported = true

// setReusePort enables SO_REUSEPORT so that several sockets can share a port
// and the kernel spreads datagrams across them (per 4-tuple hash).
func setReusePort(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return serr
}
