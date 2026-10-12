//go:build !linux

package collector

import "syscall"

const reusePortSupported = false

func setReusePort(network, address string, c syscall.RawConn) error { return nil }
