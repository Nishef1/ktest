package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

func TestWStunnelIPIsOneBelowOpenVPNTCP(t *testing.T) {
	for in, want := range map[string]string{"68.67.118.163": "68.67.118.162", "198.44.157.28": "198.44.157.27"} {
		if got, ok := wstunnelIP(in, ""); !ok || got != want {
			t.Fatalf("%s -> %s, want %s", in, got, want)
		}
	}
	if got, _ := wstunnelIP("68.67.118.163", "203.0.113.9"); got != "203.0.113.9" {
		t.Fatal("explicit -windscribe-wstunnel-ip ignored")
	}
	if _, ok := wstunnelIP("10.0.0.1", ""); ok {
		t.Fatal("x.x.x.1 has no lower neighbour")
	}
}

func TestWSOptionsValidate(t *testing.T) {
	good := []wsOptions{
		{direct: true, sni: "www.speedtest.net,a.example.com"},
		{cdnHost: "ws.example.com", cdnSNI: "front.example.net", cdnEdges: "104.16.1.1, 172.67.2.2:8443"},
	}
	for _, o := range good {
		if err := o.validate(); err != nil {
			t.Fatalf("%+v: %v", o, err)
		}
	}
	bad := []wsOptions{
		{sni: "1.2.3.4"},
		{serverIP: "192.168.1.1"},
		{path: "/udp/x"},
		{cdnHost: "https://ws.example.com"},
		{cdnHost: "104.16.1.1"},
		{cdnEdges: "104.16.1.1"},
		{cdnHost: "ws.example.com", cdnEdges: "127.0.0.1"},
	}
	for _, o := range bad {
		if err := o.validate(); err == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
}

func TestWindscribeServerCert(t *testing.T) {
	ok := &x509.Certificate{Subject: pkix.Name{CommonName: "se-010.windscribe.com"}}
	if windscribeServerCert([]*x509.Certificate{ok}) != nil {
		t.Fatal("Windscribe node refused")
	}
	other := &x509.Certificate{Subject: pkix.Name{CommonName: "evil.example"}, DNSNames: []string{"windscribe.com.evil.example"}}
	if windscribeServerCert([]*x509.Certificate{other}) == nil {
		t.Fatal("non-Windscribe server accepted")
	}
}

func TestLooksTLSorHTTP(t *testing.T) {
	if !looksTLSorHTTP([]byte{0x16, 0x03, 0x01, 0x02}) || !looksTLSorHTTP([]byte("GET / HTTP/1.1")) {
		t.Fatal("TLS/HTTP not recognised")
	}
	if looksTLSorHTTP([]byte{0x00, 0x2a, 0x38, 1, 2}) { // OpenVPN TCP hard reset
		t.Fatal("OpenVPN mistaken for TLS")
	}
}

// fakeConn answers with a label so tests can tell which dialer carried it.
func fakeConn(label string) net.Conn {
	a, b := net.Pipe()
	go func() {
		buf := make([]byte, 64)
		if _, err := b.Read(buf); err == nil {
			b.Write([]byte(label))
		}
		b.Close()
	}()
	return a
}

type dialLog struct {
	mu    sync.Mutex
	calls []string
}

func (d *dialLog) add(s string) {
	d.mu.Lock()
	d.calls = append(d.calls, s)
	d.mu.Unlock()
}

func testBridge(log *dialLog, failing map[string]bool) *wsBridge {
	carrier := func(name string) wsCarrier {
		return wsCarrier{name: name, open: func(ctx context.Context, host, port string) (net.Conn, error) {
			log.add(name)
			if failing[name] {
				return nil, errors.New("blocked")
			}
			return fakeConn(name), nil
		}}
	}
	local := func(ctx context.Context, host, port string) (net.Conn, error) {
		log.add("local:" + host)
		return fakeConn("local"), nil
	}
	b := &wsBridge{local: local, logf: func(string, ...any) {}, next: map[string]int{}}
	b.carriers = []wsCarrier{carrier("cdn"), carrier("direct"), {name: "raw", open: local}}
	return b
}

func roundTrip(t *testing.T, b *wsBridge, host string, first []byte) string {
	t.Helper()
	c, err := b.Dial(context.Background(), host, "443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(first); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, _ := io.ReadAll(c)
	return string(got)
}

var openvpnReset = []byte{0x00, 0x0e, 0x38, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0}

func TestBridgeSendsOnlyOpenVPNThroughWStunnel(t *testing.T) {
	log := &dialLog{}
	b := testBridge(log, nil)
	if got := roundTrip(t, b, "api.windscribe.com", []byte{0x16, 0x03, 0x01}); got != "local" {
		t.Fatalf("hostname went to %q", got)
	}
	if got := roundTrip(t, b, "68.67.118.163", []byte{0x16, 0x03, 0x01}); got != "local" {
		t.Fatalf("TLS to an IP went to %q", got)
	}
	if got := roundTrip(t, b, "68.67.118.163", openvpnReset); got != "cdn" {
		t.Fatalf("OpenVPN went to %q, want first carrier", got)
	}
}

func TestBridgeRotatesAndFallsBackToRawLocal(t *testing.T) {
	log := &dialLog{}
	b := testBridge(log, map[string]bool{"cdn": true, "direct": true})
	if got := roundTrip(t, b, "68.67.118.163", openvpnReset); got != "local" {
		t.Fatalf("all WStunnel carriers failed but got %q", got)
	}
	if strings.Join(log.calls, ",") != "cdn,direct,local:68.67.118.163" {
		t.Fatalf("order %v", log.calls)
	}

	log2 := &dialLog{}
	b2 := testBridge(log2, nil)
	first := roundTrip(t, b2, "68.67.118.163", openvpnReset)
	second := roundTrip(t, b2, "68.67.118.163", openvpnReset)
	if first != "cdn" || second != "direct" {
		t.Fatalf("a short-lived stream should rotate: %q then %q", first, second)
	}
}

func TestBridgeKeepsCarrierThatCarriedAVPN(t *testing.T) {
	b := testBridge(&dialLog{}, nil)
	_, done, err := b.openTunnel(context.Background(), "68.67.118.163", "443")
	if err != nil {
		t.Fatal(err)
	}
	done(2*time.Minute, 1<<20)
	if b.next["68.67.118.163:443"] != 0 {
		t.Fatal("working carrier was rotated away")
	}
}

func TestBridgeReportsUnverifiedTunnel(t *testing.T) {
	var got []smartproxy.Event
	b := testBridge(&dialLog{}, nil)
	b.report = func(e smartproxy.Event) { got = append(got, e) }
	roundTrip(t, b, "68.67.118.163", openvpnReset)
	if len(got) != 1 || !got[0].TCPOnly || got[0].OK || got[0].Path != "cdn" {
		t.Fatalf("events %+v", got)
	}
}

func TestSniffConnCloseBeforeWriteDoesNotHang(t *testing.T) {
	s := newSniffConn(context.Background(), func(context.Context, []byte) (net.Conn, func(time.Duration, int64), error) {
		t.Fatal("dialed without data")
		return nil, nil, nil
	})
	done := make(chan struct{})
	go func() { _, _ = s.Read(make([]byte, 1)); close(done) }()
	_ = s.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Read waiting for the first write ignored its deadline")
	}
	_ = s.Close()
}
