package mobilebridge

import (
	"net"
	"strings"
	"testing"
)

func TestAndroidPortsAreFixedAndValidated(t *testing.T) {
	if err := SetLocalProxyPorts(10808, 10809); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetLocalProxyPorts(10808, 10809) })
	for i := 0; i < 3; i++ {
		socks, http := localProxyAddresses(true)
		if socks != "127.0.0.1:10808" || http != "127.0.0.1:10809" {
			t.Fatalf("port unexpectedly changed: %s / %s", socks, http)
		}
	}
	for _, ports := range [][2]int{{0, 10809}, {443, 10809}, {10808, 10808}, {10808, 65536}} {
		if err := SetLocalProxyPorts(ports[0], ports[1]); err == nil {
			t.Fatalf("invalid ports accepted: %v", ports)
		}
	}
	if err := SetLocalProxyPorts(11900, 11901); err != nil {
		t.Fatal(err)
	}
	if a, b := localProxyAddresses(true); a != "127.0.0.1:11900" || b != "127.0.0.1:11901" {
		t.Fatalf("explicit user override ignored: %s %s", a, b)
	}
	if a, b := localProxyAddresses(false); a != "127.0.0.1:0" || b != "127.0.0.1:0" {
		t.Fatalf("CLI/test ephemeral listeners unexpectedly changed: %s %s", a, b)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if msg := listenerError("SOCKS5", listener.Addr().String(), errBusy{}).Error(); !strings.Contains(msg, "Settings") {
		t.Fatalf("busy port did not explain how to change it: %s", msg)
	}
}

type errBusy struct{}

func (errBusy) Error() string { return "address in use" }
