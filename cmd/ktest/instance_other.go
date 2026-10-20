//go:build !windows

package main

import (
	"errors"
	"net"
	"syscall"
)

// claimSession holds a fixed loopback port for the life of one connection,
// so a second session is refused instead of fighting over ports and keys.
func claimSession() (release func(), err error) {
	l, err := net.Listen("tcp4", "127.0.0.1:10799")
	if errors.Is(err, syscall.EADDRINUSE) {
		return nil, errAnotherSession
	}
	if err != nil {
		return func() {}, nil // cannot tell; do not block connecting
	}
	return func() { l.Close() }, nil
}
