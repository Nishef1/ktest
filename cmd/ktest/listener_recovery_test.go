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
