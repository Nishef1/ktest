package smartproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestWindscribeMethodInventoryPinsLocalCoresAndExcludesForeignRoutes(t *testing.T) {
	var hits [2]atomic.Int32
	dest := destination(t)
	p, err := New(Config{Upstreams: []Upstream{
		{Name: "plain"},
		{Name: "foreign", Addr: "127.0.0.1:1", Exit: true},
		{Name: "untrusted", Addr: "127.0.0.1:2"},
		{Name: "local A", Addr: fakeSocks(t, dest, true, &hits[0]), LocalBypass: true},
		{Name: "local B", Addr: fakeSocks(t, dest, true, &hits[1]), LocalBypass: true},
		{Name: "TLS cut", Send: func(c net.Conn, p []byte) error { _, err := c.Write(p); return err }},
		{Name: "IPv6 cut", Network: "tcp6", Send: func(net.Conn, []byte) error { return nil }},
	}})
	if err != nil {
		t.Fatal(err)
	}
	methods := p.WindscribeMethods()
	if len(methods) != 4 {
		t.Fatalf("unexpected inventory: %+v", methods)
	}
	for _, m := range methods {
		if m.IPv6Only {
			continue
		}
		if m.Name == "TLS cut" {
			if !m.TLSOnly {
				t.Fatal("TLS technique offered for raw OpenVPN")
			}
			continue
		}
		conn, err := m.Dial(context.Background(), "198.51.100.10", "443")
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	if hits[0].Load() != 1 || hits[1].Load() != 1 {
		t.Fatalf("named methods rotated anonymously instead of pinning each core: %d %d", hits[0].Load(), hits[1].Load())
	}
}

func TestWindscribeNamedMethodsStillEnforceProtectedDestinationPolicy(t *testing.T) {
	p, err := New(Config{ExitOnly: func(string) bool { return true }, Upstreams: []Upstream{
		{Name: "local", Addr: "127.0.0.1:9", LocalBypass: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range p.WindscribeMethods() {
		if conn, err := m.Dial(context.Background(), "protected.example", "443"); err == nil {
			conn.Close()
			t.Fatal("named method bypassed the protected-destination policy")
		}
	}
}

func TestWindscribeTLSMethodShapesOnlyTheCompleteInitialHello(t *testing.T) {
	hello := capturedClientHello(t, "node.example.com")
	a, peer := net.Pipe()
	defer peer.Close()
	var calls atomic.Int32
	conn := &windscribeHelloConn{Conn: a, send: func(c net.Conn, p []byte) error {
		calls.Add(1)
		if !bytes.Equal(p, hello) {
			t.Error("shaper received a partial hello or later application bytes")
		}
		_, err := c.Write(p)
		return err
	}}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	want := append(append([]byte{}, hello...), []byte("extra-later")...)
	received := make(chan []byte, 1)
	go func() { data := make([]byte, len(want)); _, _ = io.ReadFull(peer, data); received <- data }()
	for _, part := range [][]byte{hello[:1], hello[1:4], append(append([]byte{}, hello[4:]...), []byte("extra")...), []byte("-later")} {
		if n, err := conn.Write(part); err != nil || n != len(part) {
			t.Fatalf("write=%d, %v", n, err)
		}
	}
	if got := <-received; !bytes.Equal(got, want) || calls.Load() != 1 {
		t.Fatalf("TLS shaping changed/repeated bytes: calls=%d, got=%d bytes", calls.Load(), len(got))
	}
}

func TestWindscribeBuiltinTLSMethodsCompleteARealTLSHandshakeAndDataRequest(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "wrapper data") }))
	defer srv.Close()
	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{Upstreams: DesyncUpstreams()})
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range p.WindscribeMethods() {
		if method.IPv6Only {
			continue
		} // this fixture advertises an IPv4 carrier
		t.Run(method.Name, func(t *testing.T) {
			conn, err := method.Dial(context.Background(), host, port)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			// Only the local fixture's self-signed certificate is skipped.
			client := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "node.example.com"})
			defer client.Close()
			if err := client.Handshake(); err != nil {
				t.Fatalf("wrapper handshake failed: %v", err)
			}
			if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: node.example.com\r\nConnection: close\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(client)
			if err != nil || !bytes.Contains(body, []byte("wrapper data")) {
				t.Fatalf("TLS stream lost application data: %v", err)
			}
		})
	}
}
