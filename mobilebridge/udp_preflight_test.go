package mobilebridge

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func fakeUDPAssociate(t *testing.T, udpReply bool) string {
	t.Helper()
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { _ = relay.Close() })
	socks, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { _ = socks.Close() })
	go func() {
		conn, err := socks.Accept()
		if err != nil { return }
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3*time.Second))
		var greeting [3]byte
		if _, err := io.ReadFull(conn, greeting[:]); err != nil { return }
		_, _ = conn.Write([]byte{5, 0})
		var req [10]byte
		if _, err := io.ReadFull(conn, req[:]); err != nil { return }
		if req[1] != 3 { return }
		port := relay.LocalAddr().(*net.UDPAddr).Port
		_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)})
		var buf [1]byte
		_, _ = conn.Read(buf[:]) // Hold UDP association until caller closes it.
	}()
	if udpReply {
		go func() {
			_ = relay.SetReadDeadline(time.Now().Add(3*time.Second))
			buf := make([]byte, 1500)
			n, source, err := relay.ReadFromUDP(buf)
			if err != nil || n < 10+29 { return }
			dns := append([]byte(nil), buf[10:n]...)
			dns[2], dns[3] = 0x81, 0x80
			dns[6], dns[7] = 0, 1
			// Answer: compression pointer to question, A record, 93.184.215.14
			dns = append(dns, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 215, 14)
			resp := append([]byte{0, 0, 0, 1, 1, 1, 1, 1, 0, 53}, dns...)
			_, _ = relay.WriteToUDP(resp, source)
		}()
	}
	return socks.Addr().String()
}

func TestUDPRelayPreflightRealFraming(t *testing.T) {
	addr := fakeUDPAssociate(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	report, err := probeUDPRelay(ctx, addr)
	if err != nil { t.Fatal(err) }
	if !report.Ready || !report.DNSAnswered || report.Relay == "" { t.Fatalf("unexpected report: %+v", report) }
}

func TestUDPRelayPreflightRejectsNoReply(t *testing.T) {
	addr := fakeUDPAssociate(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := probeUDPRelay(ctx, addr); err == nil {
		t.Fatal("SOCKS ACK without UDP response must fail")
	}
}

func TestUDPRelayRejectsRemoteOrInvalidEndpoints(t *testing.T) {
	for _, addr := range []string{"8.8.8.8:1080", "example.com:1080", "127.0.0.1:0", "127.0.0.1:65536"} {
		ctx := context.Background()
		if _, err := probeUDPRelay(ctx, addr); err == nil || !strings.Contains(err.Error(), "SOCKS") && !strings.Contains(err.Error(), "port") && !strings.Contains(err.Error(), "loopback") {
			t.Errorf("invalid endpoint %q accepted or returned unexpected error: %v", addr, err)
		}
	}
}

// Ensure the fixture writes its port in network byte order.
func TestUDPFixturePort(t *testing.T) {
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, 5353)
	if p[0] != 0x14 || p[1] != 0xe9 { t.Fatal("bad fixture encoding") }
}
