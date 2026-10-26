package mobilebridge

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
)

// Android listener defaults do not change between sessions. A different
// application can use these ports; in that case fail clearly, never switch
// silently to a random port. All listeners bind to loopback only.
const (
	defaultSOCKSPort = 10808
	defaultHTTPPort  = 10809
)

var listenerPortMu sync.RWMutex
var listenerSOCKS, listenerHTTP = defaultSOCKSPort, defaultHTTPPort

func validListenerPorts(socks, http int) error {
	if socks < 1024 || socks > 65535 || http < 1024 || http > 65535 {
		return errors.New("listener ports must be between 1024 and 65535")
	}
	if socks == http {
		return errors.New("SOCKS5 and HTTP must use different ports")
	}
	return nil
}

// SetLocalProxyPorts accepts explicit user preferences. A zero port is never
// accepted here; tests and CLI sessions may still request an ephemeral socket.
func SetLocalProxyPorts(socks, http int) error {
	if err := validListenerPorts(socks, http); err != nil {
		return err
	}
	proxyStartMu.Lock()
	defer proxyStartMu.Unlock()
	proxyMu.Lock()
	defer proxyMu.Unlock()
	if activeProxy != nil || pendingProxy != nil {
		return errors.New("disconnect before changing local proxy ports")
	}
	listenerPortMu.Lock()
	listenerSOCKS, listenerHTTP = socks, http
	listenerPortMu.Unlock()
	return nil
}

func localProxyAddresses(android bool) (string, string) {
	if !android {
		return "127.0.0.1:0", "127.0.0.1:0"
	}
	listenerPortMu.RLock()
	defer listenerPortMu.RUnlock()
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(listenerSOCKS)),
		net.JoinHostPort("127.0.0.1", strconv.Itoa(listenerHTTP))
}

func listenerError(name, address string, err error) error {
	return fmt.Errorf("%s port %s is unavailable: %w; disconnect the other app or change ports in Settings", name, address, err)
}
