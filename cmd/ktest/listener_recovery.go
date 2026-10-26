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

// recoverSessionListen keeps Windscribe's actual proxy endpoints consistent
// with its explicit HTTP Proxy Settings. An automatically relocated listener
// would leave Windscribe connecting to 10801 while KTest listens elsewhere.
// All other modes retain the previous auto-recovery policy.
func recoverSessionListen(mode ConnectionMode, requested, stock string) (string, bool, error) {
	if !mode.isWindscribe() {
		return recoverLoopbackListen(requested, stock)
	}
	address, _, err := recoverLoopbackListen(requested, "")
	if err != nil {
		return "", false, fmt.Errorf("Windscribe proxy port %s is occupied; close the conflicting listener or explicitly change the KTest listener and Windscribe HTTP Proxy Settings together: %w", requested, err)
	}
	return address, false, nil
}
