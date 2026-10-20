package main

import (
	"fmt"
	"net"
)

// recoverLoopbackListen refuses to take ownership of another app's socket.
// Only the stock KTest port may move automatically; explicit user ports
// remain fixed and report their exact conflict. The kernel chooses a free
// ephemeral loopback port rather than guessing around KTest helper ports.
// Its short-lived reservation is a preflight check, not ownership: the real
// StartHTTP/StartSOCKS bind still handles any race.
func recoverLoopbackListen(requested, stock string) (string, bool, error) {
	l, err := net.Listen("tcp", requested)
	if err == nil {
		_ = l.Close()
		return requested, false, nil
	}
	if requested != stock {
		return "", false, fmt.Errorf("requested listener %s unavailable: %w", requested, err)
	}
	host, _, splitErr := net.SplitHostPort(stock)
	if splitErr != nil || host == "" {
		return "", false, fmt.Errorf("invalid default listener %q: %w", stock, err)
	}
	alternate, altErr := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if altErr != nil {
		return "", false, fmt.Errorf("default listener %s is busy and no loopback fallback is available: %w", stock, altErr)
	}
	address := alternate.Addr().String()
	_ = alternate.Close()
	return address, true, nil
}
