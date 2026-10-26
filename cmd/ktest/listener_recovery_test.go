package main

import (
	"net"
	"testing"
)

func TestDefaultListenerRelocatesWithoutClosingOwner(t *testing.T) {
	owner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	occupied := owner.Addr().String()
	chosen, changed, err := recoverLoopbackListen(occupied, occupied)
	if err != nil || !changed || chosen == occupied {
		t.Fatalf("default collision did not recover: %s %v %v", chosen, changed, err)
	}
	if peer, err := net.Dial("tcp", occupied); err != nil {
		t.Fatalf("existing listener was disrupted: %v", err)
	} else {
		peer.Close()
	}
}

func TestExplicitPortConflictMustFail(t *testing.T) {
	owner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	address := owner.Addr().String()
	if _, changed, err := recoverLoopbackListen(address, connectListenDefault); err == nil || changed {
		t.Fatal("explicit occupied port silently changed")
	}
}

func TestFreeDefaultPortKeepsConfiguration(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	probe.Close()
	chosen, changed, err := recoverLoopbackListen(address, address)
	if err != nil || changed || chosen != address {
		t.Fatalf("unused port should keep exact address: %q %v %v", chosen, changed, err)
	}
}

func TestWindscribeListenersNeverRelocateSilently(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	busy := listener.Addr().String()
	for _, mode := range []ConnectionMode{ModeWindscribe, ModeWindscribeAether} {
		chosen, changed, err := recoverSessionListen(mode, busy, busy)
		if err == nil || chosen != "" || changed {
			t.Fatalf("%s silently moved Windscribe's occupied proxy port: %s %t %v", mode, chosen, changed, err)
		}
	}
	// Other modes keep their established automatic recovery behavior.
	chosen, changed, err := recoverSessionListen(ModeBalanced, busy, busy)
	if err != nil || !changed || chosen == busy {
		t.Fatalf("non-Windscribe default collision did not recover: %s %t %v", chosen, changed, err)
	}
	if conn, err := net.Dial("tcp", busy); err != nil {
		t.Fatalf("another app's listener was disrupted: %v", err)
	} else {
		_ = conn.Close()
	}
}

func TestWindscribeFreeListenerRemainsFixed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	chosen, changed, err := recoverSessionListen(ModeWindscribe, address, connectHTTPDefault)
	if err != nil || changed || chosen != address {
		t.Fatalf("Windscribe listener was changed on a free port: %s %t %v", chosen, changed, err)
	}
}

func TestWindscribeProxyPortAndLoopbackValidation(t *testing.T) {
	for _, address := range []string{"127.0.0.1:10800", "127.0.0.1:10801", "localhost:12000", "[::1]:10801"} {
		if err := validateProxyBind(address, true); err != nil {
			t.Fatalf("valid Windscribe loopback listener %s rejected: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:10801", "[::]:10801", "192.168.1.20:10801", "0.0.0.0:0",
		"127.0.0.1:0", "127.0.0.1:443", "127.0.0.1:65536", "example.com:10801", "127.0.0.1:bad"} {
		if err := validateProxyBind(address, true); err == nil {
			t.Fatalf("unsafe or unstable Windscribe proxy listener %s was accepted", address)
		}
	}
	// Other modes can request an ephemeral loopback port for local tests,
	// but never wildcard/LAN HTTP listener.
	if err := validateProxyBind("127.0.0.1:0", false); err != nil {
		t.Fatalf("existing ephemeral port mode should remain supported: %v", err)
	}
	if err := validateProxyBind("0.0.0.0:10801", false); err == nil {
		t.Fatal("unauthenticated HTTP proxy was exposed to LAN")
	}
}

func TestValidateWindscribeProxyOptionsRejectUnsafeBinds(t *testing.T) {
	for _, mode := range []ConnectionMode{ModeWindscribe, ModeWindscribeAether} {
		o := defaultConnectOptions(t.TempDir())
		o.mode = mode
		o.tun = false
		o.listen = "127.0.0.1:10800"
		o.httpListen = "127.0.0.1:10801"
		if err := validateConnectOptions(o); err != nil {
			t.Fatalf("%s default endpoints rejected: %v", mode, err)
		}
		o.httpListen = "0.0.0.0:10801"
		if err := validateConnectOptions(o); err == nil {
			t.Fatalf("%s accepted LAN HTTP proxy", mode)
		}
		o.httpListen = "127.0.0.1:10801"
		o.listen = "127.0.0.1:0"
		if err := validateConnectOptions(o); err == nil {
			t.Fatalf("%s accepted an unstable SOCKS port", mode)
		}
	}
}
