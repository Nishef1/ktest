package mobilebridge

import (
	"context"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNativeBootstrapDNSRelaysWireQueriesAndStopsWithOwner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	address, stop, err := startNativeDNS(ctx, func(_ context.Context, query []byte) ([]byte, error) {
		return append([]byte(nil), query...), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	c, err := net.Dial("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	query := []byte("bounded DNS wire query")
	if _, err = c.Write(query); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(query))
	if _, err = io.ReadFull(c, response); err != nil || string(response) != string(query) {
		t.Fatalf("query did not use supplied encrypted exchanger: %q %v", response, err)
	}
	cancel()
	stop()
	if listener, err := net.ListenPacket("udp4", address); err != nil {
		t.Fatal("owner cancellation left DNS socket open:", err)
	} else {
		listener.Close()
	}
}

func TestPsiphonDNSOverlayContainsOnlyOwnedResolverAndIsRemoved(t *testing.T) {
	dir := t.TempDir()
	path, stop, err := preparePsiphonDNS(context.Background(), dir, "profile")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	raw, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), "127.0.0.1:") || !strings.Contains(string(raw), "DNSResolverPreferredAlternateServers") {
		t.Fatalf("missing native DNS bootstrap configuration: %s %v", raw, err)
	}
	stop()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("temporary DNS configuration survived native shutdown")
	}
}
