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
