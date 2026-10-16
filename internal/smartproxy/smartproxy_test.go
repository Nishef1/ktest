package smartproxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// clientHello is a minimal record that looks like a TLS ClientHello to the
// proxy: handshake record, version 3.1, length, handshake type 1.
func clientHello() []byte {
	body := []byte{0x01, 0, 0, 4, 3, 3, 0, 0}
	rec := []byte{0x16, 3, 1, 0, byte(len(body))}
	return append(rec, body...)
}

// serverHello answers with a TLS handshake record header plus payload.
var serverHello = []byte{0x16, 3, 3, 0, 4, 2, 0, 0, 0}

// destination replies to any first bytes with a ServerHello-looking record.
func destination(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				if n, _ := c.Read(buf); n > 0 {
					_, _ = c.Write(serverHello)
				}
			}()
		}
	}()
	return l.Addr().String()
}

// fakeSocks is a SOCKS5 upstream. forward=false simulates a path where the
// connection is accepted but killed once the ClientHello arrives.
func fakeSocks(t *testing.T, dest string, forward bool, hits *atomic.Int32) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if _, _, err := socksRequest(c); err != nil {
					return
				}
				hits.Add(1)
				_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				if !forward {
					buf := make([]byte, 4096)
					_, _ = c.Read(buf)
					return // dropped: no server response
				}
				d, err := net.Dial("tcp", dest)
				if err != nil {
					return
				}
				defer d.Close()
				pipe(c, d)
			}()
		}
	}()
	return l.Addr().String()
}

func startProxy(t *testing.T, ups []Upstream) (*Proxy, string) {
	t.Helper()
	p, err := New(Config{Upstreams: ups, Stagger: 80 * time.Millisecond, FirstByteTimeout: 600 * time.Millisecond, ConnectTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go p.Serve(ctx, l)
	return p, l.Addr().String()
}

// viaProxy opens a SOCKS5 connection to the proxy, sends flight and returns
// whatever comes back before the deadline.
func viaProxy(t *testing.T, proxy, host, port string, flight []byte) []byte {
	t.Helper()
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	if err := socksConnect(c, host, port); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(flight); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 64)
	n, _ := io.ReadAtLeast(c, got, len(serverHello))
	return got[:n]
}

func TestRaceSkipsBlockedPathAndLearnsWinner(t *testing.T) {
	dest := destination(t)
	var blockedHits, goodHits atomic.Int32
	blocked := fakeSocks(t, dest, false, &blockedHits)
	good := fakeSocks(t, dest, true, &goodHits)
	// The blocked path is listed first, so the first connection must replay.
	p, addr := startProxy(t, []Upstream{{"blocked", blocked}, {"good", good}})
	host, port, _ := net.SplitHostPort(dest)

	if got := viaProxy(t, addr, "site.example", port, clientHello()); !bytes.Equal(got, serverHello) {
		t.Fatalf("first connection got %x", got)
	}
	if got := p.Winners()["site.example"]; got != "good" {
		t.Fatalf("winner not remembered: %q", got)
	}
	before := blockedHits.Load()
	if got := viaProxy(t, addr, "site.example", port, clientHello()); !bytes.Equal(got, serverHello) {
		t.Fatalf("second connection got %x", got)
	}
	// With the winner remembered the blocked path is not tried first; it may
	// join after the stagger but the good path answers immediately.
	if now := blockedHits.Load(); now > before+1 {
		t.Fatalf("blocked path retried too often: %d -> %d", before, now)
	}
	_ = host
	stats := p.Stats()
	if stats[0].Name != "good" || stats[0].Wins != 2 {
		t.Fatalf("stats %+v", stats)
	}
}

func TestRaceFailsWhenEveryPathIsBlocked(t *testing.T) {
	dest := destination(t)
	var h1, h2 atomic.Int32
	_, addr := startProxy(t, []Upstream{{"a", fakeSocks(t, dest, false, &h1)}, {"b", fakeSocks(t, dest, false, &h2)}})
	_, port, _ := net.SplitHostPort(dest)
	if got := viaProxy(t, addr, "site.example", port, clientHello()); len(got) != 0 {
		t.Fatalf("unexpected data %x", got)
	}
}

func TestNonTLSTrafficUsesBestPathWithoutRacing(t *testing.T) {
	dest := destination(t)
	var hits atomic.Int32
	_, addr := startProxy(t, []Upstream{{"only", fakeSocks(t, dest, true, &hits)}})
	_, port, _ := net.SplitHostPort(dest)
	if got := viaProxy(t, addr, "plain.example", port, []byte("GET / HTTP/1.1\r\n\r\n")); !bytes.Equal(got, serverHello) {
		t.Fatalf("got %x", got)
	}
}

func TestUpstreamValidationAndTLSDetection(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("empty upstream list accepted")
	}
	if _, err := New(Config{Upstreams: []Upstream{{"a", "x"}, {"a", "y"}}}); err == nil {
		t.Fatal("duplicate names accepted")
	}
	if !isTLSFlight(clientHello()) || isTLSFlight([]byte("GET / HTTP/1.1")) || isTLSFlight(nil) {
		t.Fatal("TLS flight detection wrong")
	}
}
