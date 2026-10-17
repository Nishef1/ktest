package wstunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type writeStartedConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *writeStartedConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

func TestCloseUnblocksStalledWriter(t *testing.T) {
	a, z := net.Pipe()
	defer z.Close()
	defer a.Close()
	leg := &writeStartedConn{Conn: a, started: make(chan struct{})}
	c := &Conn{c: leg, r: bufio.NewReader(leg)}
	written := make(chan error, 1)
	go func() { _, err := c.Write([]byte("blocked")); written <- err }()
	<-leg.started // writer holds wmu and the peer will never read
	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close waited indefinitely for a blocked WebSocket writer")
	}
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("stalled write unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Close left the writer blocked")
	}
}

func TestDialReportsTCPFailureWithoutLosingCause(t *testing.T) {
	blocked := errors.New("destination blocked")
	_, err := Dial(context.Background(), Config{Addr: "203.0.113.1:443", Host: "203.0.113.1", Dial: func(context.Context, string) (net.Conn, error) { return nil, blocked }})
	var stage *StageError
	if !errors.Is(err, blocked) || !errors.As(err, &stage) || stage.Stage != "tcp" {
		t.Fatalf("TCP stage and cause must survive: %v", err)
	}
}

// readClientFrame reads one masked client frame.
func readClientFrame(r *bufio.Reader) (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	if h[1]&0x80 == 0 {
		return 0, nil, errors.New("client frame not masked")
	}
	n := uint64(h[1] & 0x7F)
	switch n {
	case 126:
		var b [2]byte
		io.ReadFull(r, b[:])
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		io.ReadFull(r, b[:])
		n = binary.BigEndian.Uint64(b[:])
	}
	var mask [4]byte
	io.ReadFull(r, mask[:])
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	for i := range p {
		p[i] ^= mask[i&3]
	}
	return h[0] & 0x0F, p, nil
}

func serverFrame(op byte, p []byte) []byte {
	f := []byte{0x80 | op}
	switch {
	case len(p) < 126:
		f = append(f, byte(len(p)))
	case len(p) <= 0xFFFF:
		f = append(f, 126, byte(len(p)>>8), byte(len(p)))
	default:
		f = append(f, 127)
		f = binary.BigEndian.AppendUint64(f, uint64(len(p)))
	}
	return append(f, p...)
}

// wsEcho is a WStunnel-like server: it upgrades only on wantPath, pings once,
// then echoes every binary message back.
func wsEcho(t *testing.T, wantPath string, hosts chan<- string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wantPath || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.NotFound(w, r)
			return
		}
		if hosts != nil {
			hosts <- r.Host
		}
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + acceptKey(r.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n")
		rw.Write(serverFrame(opPing, []byte("hi")))
		rw.Flush()
		for {
			op, p, err := readClientFrame(rw.Reader)
			if err != nil {
				return
			}
			switch op {
			case opBinary:
				rw.Write(serverFrame(opBinary, p))
				rw.Flush()
			case opClose:
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
}

func TestRoundTripCarriesStreamAndAnswersPing(t *testing.T) {
	hosts := make(chan string, 1)
	srv := wsEcho(t, DefaultPath, hosts)
	c, err := Dial(context.Background(), Config{Addr: srv.Listener.Addr().String(), SNI: "www.speedtest.net", Host: "203.0.113.7", Dial: dialTCP})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if h := <-hosts; h != "203.0.113.7" {
		t.Fatalf("Host header %q", h)
	}
	want := make([]byte, 100<<10) // larger than one frame
	rand.Read(want)
	go c.Write(want)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("stream corrupted")
	}
}

func TestUpgradeRefusedIsAnError(t *testing.T) {
	srv := wsEcho(t, "/other", nil)
	_, err := Dial(context.Background(), Config{Addr: srv.Listener.Addr().String(), Host: "x", Dial: dialTCP})
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("want HTTP 404 error, got %v", err)
	}
	var stage *StageError
	if !errors.As(err, &stage) || stage.Stage != "websocket" {
		t.Fatalf("wrong failure boundary: %v", err)
	}
}

func TestVerifyRejectsUntrustedCertificate(t *testing.T) {
	srv := wsEcho(t, DefaultPath, nil)
	_, err := Dial(context.Background(), Config{Addr: srv.Listener.Addr().String(), SNI: "example.com", Host: "example.com", Verify: true, Dial: dialTCP})
	if err == nil {
		t.Fatal("self-signed CDN certificate accepted")
	}
}

func TestVerifyPeerDecides(t *testing.T) {
	srv := wsEcho(t, DefaultPath, nil)
	refuse := func([]*x509.Certificate) error { return errors.New("not windscribe") }
	_, err := Dial(context.Background(), Config{Addr: srv.Listener.Addr().String(), Host: "x", VerifyPeer: refuse, Dial: dialTCP})
	if err == nil || !strings.Contains(err.Error(), "not windscribe") {
		t.Fatalf("VerifyPeer ignored: %v", err)
	}
	var stage *StageError
	if !errors.As(err, &stage) || stage.Stage != "tls" {
		t.Fatalf("wrong failure boundary: %v", err)
	}
	seen := 0
	accept := func(certs []*x509.Certificate) error { seen = len(certs); return nil }
	c, err := Dial(context.Background(), Config{Addr: srv.Listener.Addr().String(), Host: "x", VerifyPeer: accept, Dial: dialTCP})
	if err != nil || seen == 0 {
		t.Fatalf("accepting VerifyPeer: %v, %d certs", err, seen)
	}
	c.Close()
}

func TestNotAWebSocketServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer srv.Close()
	_, err := Dial(context.Background(), Config{Addr: srv.Listener.Addr().String(), Host: "x", Dial: dialTCP})
	if err == nil {
		t.Fatal("101 without a WebSocket accept key was trusted")
	}
}

func TestConfigValidation(t *testing.T) {
	for _, c := range []Config{
		{Host: "x", Dial: dialTCP},
		{Addr: "a:443", Dial: dialTCP},
		{Addr: "a:443", Host: "x", Dial: dialTCP, Verify: true},
		{Addr: "a:443", Host: "x", Dial: dialTCP, Path: "nope"},
	} {
		if _, err := Dial(context.Background(), c); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}

func TestStealthCarriesRawStreamOverTLS(t *testing.T) {
	cert := httptest.NewTLSServer(http.NotFoundHandler())
	defer cert.Close()
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: cert.TLS.Certificates})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c) // echo
	}()
	c, err := DialStealth(context.Background(), Config{Addr: l.Addr().String(), SNI: "www.speedtest.net", Dial: dialTCP})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("openvpn")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 7)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "openvpn" {
		t.Fatalf("%q %v", got, err)
	}
}

type shortWebSocketWriteConn struct {
	net.Conn
	maxWrite int
}

func (c *shortWebSocketWriteConn) Write(p []byte) (int, error) {
	if len(p) > c.maxWrite {
		p = p[:c.maxWrite]
	}
	return c.Conn.Write(p)
}

func TestClientWebSocketFrameSurvivesShortSuccessfulWrites(t *testing.T) {
	a, peer := net.Pipe()
	defer a.Close()
	defer peer.Close()
	conn := &Conn{c: &shortWebSocketWriteConn{Conn: a, maxWrite: 3}, r: bufio.NewReader(a)}
	received := make(chan []byte, 1)
	failed := make(chan error, 1)
	go func() {
		_, payload, err := readClientFrame(bufio.NewReader(peer))
		if err != nil {
			failed <- err
			return
		}
		received <- payload
	}()
	payload := bytes.Repeat([]byte("OpenVPN handshake bytes"), 20)
	n, err := conn.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("short frame writes lost payload: %d/%d, %v", n, len(payload), err)
	}
	select {
	case got := <-received:
		if !bytes.Equal(got, payload) {
			t.Fatal("WebSocket framing was corrupted by short successful writes")
		}
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("failed to decode complete WebSocket frame")
	}
}
