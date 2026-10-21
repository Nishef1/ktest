package smartproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func packetProxy(t *testing.T, cfg Config) (*Proxy, string, context.CancelFunc) {
	t.Helper()
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx, l) }()
	return p, l.Addr().String(), cancel
}

func associate(t *testing.T, address string) *udpExit {
	t.Helper()
	e, err := dialUDPExit(context.Background(), &upstreamState{Upstream: Upstream{Addr: address}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.close)
	return e
}

func receiveUDP(t *testing.T, e *udpExit, want []byte) {
	t.Helper()
	_ = e.socket.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 65535)
	n, err := e.socket.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("UDP response = %x, want %x", buf[:n], want)
	}
}

func TestSOCKSUDPDNSAndTCPDNSUseEncryptedExchange(t *testing.T) {
	var exchanges atomic.Int32
	query := []byte("complete wire DNS fixture")
	response := []byte("encrypted DNS response")
	_, address, cancel := packetProxy(t, Config{
		Upstreams: PlainUpstreams(),
		ExchangeDNS: func(ctx context.Context, message []byte) ([]byte, error) {
			exchanges.Add(1)
			if !bytes.Equal(message, query) {
				return nil, errors.New("query changed")
			}
			return response, nil
		},
	})
	e := associate(t, address)
	for _, host := range []string{"1.1.1.1", "2606:4700:4700::1111", "dns.example"} {
		packet, _ := udpPacket(host, "53", query)
		if _, err := e.socket.Write(packet); err != nil {
			t.Fatal(err)
		}
		want, _ := udpPacket(host, "53", response)
		receiveUDP(t, e, want)
	}
	conn, err := DialVia(context.Background(), address, "1.1.1.1", "53", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	_, _ = conn.Write(append(frame, query...))
	want := append(binary.BigEndian.AppendUint16(nil, uint16(len(response))), response...)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("TCP DNS = %x, %v", got, err)
	}
	if exchanges.Load() != 4 {
		t.Fatalf("not all DNS traffic used the exchange: %d", exchanges.Load())
	}
	cancel()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("session cancellation left TCP DNS open")
	}
}

func TestUDPDoesNotFallBackToDirectOrUnverifiedExit(t *testing.T) {
	for _, upstream := range []Upstream{{Name: "direct"}, {Name: "unverified", Addr: "127.0.0.1:9", Exit: true}} {
		t.Run(upstream.Name, func(t *testing.T) {
			p, _, _ := packetProxy(t, Config{Upstreams: []Upstream{upstream}})
			if _, err := p.openUDPExit(context.Background(), "chatgpt.com", "443"); err == nil {
				t.Fatal("unsafe UDP path accepted")
			}
		})
	}
}

func TestUDPForeignRelayPreservesIPv6AndStopsWhenExitRemoved(t *testing.T) {
	// A real local SOCKS5 server echoes datagrams through its encrypted DNS
	// exchange, standing in for the separately verified native exit transport.
	_, upstream, _ := packetProxy(t, Config{Upstreams: PlainUpstreams(),
		ExchangeDNS: func(_ context.Context, b []byte) ([]byte, error) { return b, nil },
	})
	p, address, _ := packetProxy(t, Config{Upstreams: []Upstream{
		{Name: "verified", Addr: upstream, Exit: true, AIEligible: true},
	}})
	e := associate(t, address)
	packet, _ := udpPacket("2606:4700:4700::1111", "53", []byte("IPv6 UDP payload"))
	_, _ = e.socket.Write(packet)
	receiveUDP(t, e, packet)
	p.Remove("verified")
	_, _ = e.socket.Write(packet)
	_ = e.socket.SetReadDeadline(time.Now().Add(120 * time.Millisecond))
	if _, err := e.socket.Read(make([]byte, 2048)); err == nil {
		t.Fatal("removed exit still carried UDP")
	}
}

func TestUDPAssociationClosesWithTCPControl(t *testing.T) {
	started := make(chan struct{}, 1)
	finished := make(chan struct{}, 1)
	_, address, _ := packetProxy(t, Config{Upstreams: PlainUpstreams(),
		ExchangeDNS: func(ctx context.Context, _ []byte) ([]byte, error) {
			started <- struct{}{}
			<-ctx.Done()
			finished <- struct{}{}
			return nil, ctx.Err()
		},
	})
	e := associate(t, address)
	packet, _ := udpPacket("1.1.1.1", "53", []byte("query"))
	_, _ = e.socket.Write(packet)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("query never started")
	}
	_ = e.control.Close()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("closing TCP did not cancel outstanding DNS")
	}
}

func TestUDPRejectsFragmentedAndMalformedDatagrams(t *testing.T) {
	valid, _ := udpPacket("example.com", "443", []byte("hello"))
	for n := 0; n < len(valid)-5; n++ {
		if _, _, _, err := parseUDPPacket(valid[:n]); err == nil {
			t.Fatalf("accepted truncated datagram %x", valid[:n])
		}
	}
	valid[2] = 1
	if _, _, _, err := parseUDPPacket(valid); err == nil {
		t.Fatal("accepted UDP fragments without reassembly")
	}
}

func TestBalancedUDPUsesVerifiedExitInsteadOfFrozenLocalTCPMethod(t *testing.T) {
	p, err := New(Config{
		Frozen:   &FrozenRoutes{Default: "local", Protected: "foreign"},
		ExitOnly: func(host string) bool { return host == "private.example" },
		Upstreams: []Upstream{
			{Name: "local", LocalBypass: true, Addr: "127.0.0.1:9999"},
			{Name: "foreign", Addr: "127.0.0.1:9998", Exit: true, AIEligible: true},
			{Name: "unverified", Addr: "127.0.0.1:9997", Exit: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	udp := p.udpCandidates("public.example")
	if len(udp) != 1 || udp[0].Name != "foreign" {
		t.Fatalf("frozen local TCP method blocked the permitted UDP exit: %+v", udp)
	}
	if list := p.order("public.example", "443"); len(list) != 1 || list[0].Name != "local" {
		t.Fatal("UDP selection unexpectedly changed TCP routing")
	}
	p.aiPinned = "missing"
	if got := p.udpCandidates("public.example"); len(got) != 0 {
		t.Fatalf("UDP fell back from missing pinned exit: %+v", got)
	}
	p.aiPinned = ""
	p.cfg.Frozen.Protected = ""
	if got := p.udpCandidates("private.example"); len(got) != 0 {
		t.Fatalf("protected UDP escaped empty frozen exit pin: %+v", got)
	}
}

// Aether mode: a working WARP carrier that geolocates to Iran relays UDP
// (QUIC, calls) for ordinary names, end to end through SOCKS5 UDP ASSOCIATE,
// while protected names never reach it.
func TestAetherUDPRidesWorkingCarrierEndToEnd(t *testing.T) {
	_, upstream, _ := packetProxy(t, Config{Upstreams: PlainUpstreams(),
		ExchangeDNS: func(_ context.Context, b []byte) ([]byte, error) { return b, nil },
	})
	_, address, _ := packetProxy(t, Config{
		Upstreams:     []Upstream{{Name: "carrier", Addr: upstream, Exit: true}},
		ExitOnly:      func(host string) bool { return host == "chatgpt.com" },
		ExitRequired:  func(string) bool { return true },
		VerifyCarrier: func(context.Context, Upstream) error { return nil },
	})
	e := associate(t, address)
	ordinary, _ := udpPacket("www.youtube.com", "53", []byte("QUIC-like payload"))
	_, _ = e.socket.Write(ordinary)
	receiveUDP(t, e, ordinary)

	protected := associate(t, address)
	packet, _ := udpPacket("chatgpt.com", "53", []byte("AI payload"))
	_, _ = protected.socket.Write(packet)
	_ = protected.socket.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := protected.socket.Read(make([]byte, 2048)); err == nil {
		t.Fatal("protected UDP rode an Iran-located carrier")
	}
}
