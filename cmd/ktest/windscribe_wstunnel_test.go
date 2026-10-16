package main

import (
	"bytes"
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
func TestStealthIsOneAboveOpenVPNTCP(t *testing.T) {
	if got, ok := neighbourIP("68.67.118.163", +1); !ok || got != "68.67.118.164" {
		t.Fatalf("got %s", got)
	}
	if _, ok := neighbourIP("10.0.0.254", +1); ok {
		t.Fatal("x.x.x.255 is not a node address")
	}
}

// fakeServer answers the first packet with label after delay; silent never
// answers.
func fakeServer(label string, delay time.Duration, silent bool, closed chan<- string) net.Conn {
	a, b := net.Pipe()
	go func() {
		defer func() {
			b.Close()
			if closed != nil {
				closed <- label
			}
		}()
		buf := make([]byte, 64)
		if _, err := b.Read(buf); err != nil {
			return
		}
		if silent {
			_, _ = b.Read(buf) // until closed
			return
		}
		time.Sleep(delay)
		if _, err := b.Write([]byte(label)); err != nil {
			return
		}
		_, _ = b.Read(buf) // keep the stream open until closed
	}()
	return a
}

type carrierSpec struct {
	name   string
	fail   bool
	silent bool
	delay  time.Duration
}

type dialLog struct {
	mu     sync.Mutex
	calls  []string
	closed chan string
}

func (d *dialLog) add(s string) {
	d.mu.Lock()
	d.calls = append(d.calls, s)
	d.mu.Unlock()
}

func testBridge(log *dialLog, specs ...carrierSpec) *wsBridge {
	local := func(ctx context.Context, host, port string) (net.Conn, error) {
		log.add("local:" + host)
		return fakeServer("local", 0, false, nil), nil
	}
	b := newWSBridge(wsOptions{}, local, nil, func(string, ...any) {})
	b.stagger = 5 * time.Millisecond
	b.candidates = func(string) []wsCarrier {
		var cs []wsCarrier
		for _, s := range specs {
			cs = append(cs, wsCarrier{name: s.name, open: func(ctx context.Context, host, port string) (net.Conn, error) {
				log.add(s.name)
				if s.fail {
					return nil, errors.New("blocked")
				}
				return fakeServer(s.name, s.delay, s.silent, log.closed), nil
			}})
		}
		return cs
	}
	return b
}

// roundTrip writes first and returns what the carrier answered.
func roundTrip(t *testing.T, b *wsBridge, host string, first []byte) (string, net.Conn) {
	t.Helper()
	c, err := b.Dial(context.Background(), host, "443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(first); err != nil {
		c.Close()
		return "error: " + err.Error(), nil
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if n == 0 && err != nil {
		c.Close()
		return "error: " + err.Error(), nil
	}
	return string(buf[:n]), c
}

var openvpnReset = []byte{0x00, 0x0e, 0x38, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0}

func TestRaceReplaysJunkAndLaterWritesToLateCarrier(t *testing.T) {
	b := testBridge(&dialLog{})
	junk := bytes.Repeat([]byte{0x55}, 88)
	want := append(bytes.Repeat(junk, 5), openvpnReset...)
	firstReceived := make(chan struct{})
	releaseLate := make(chan struct{})
	b.candidates = func(string) []wsCarrier {
		return []wsCarrier{
			{name: "silent", open: func(context.Context, string, string) (net.Conn, error) {
				a, z := net.Pipe()
				go func() {
					defer z.Close()
					buf := make([]byte, len(want))
					if _, err := io.ReadFull(z, buf); err == nil {
						close(firstReceived)
					}
					_, _ = io.Copy(io.Discard, z)
				}()
				return a, nil
			}},
			{name: "WStunnel late", open: func(ctx context.Context, _, _ string) (net.Conn, error) {
				select {
				case <-releaseLate:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				a, z := net.Pipe()
				go func() {
					defer z.Close()
					buf := make([]byte, len(want))
					if _, err := io.ReadFull(z, buf); err != nil || !bytes.Equal(buf, want) {
						return
					}
					if _, err := z.Write([]byte("answered")); err == nil {
						_, _ = io.Copy(z, z) // verify the stream continues after selection
					}
				}()
				return a, nil
			}},
		}
	}
	c, err := b.Dial(context.Background(), "68.67.118.163", "443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	writeDone := make(chan error, 1)
	go func() {
		for range 5 {
			if _, err := c.Write(junk); err != nil {
				writeDone <- err
				return
			}
		}
		_, err := c.Write(openvpnReset)
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("client writes blocked before the handshake: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client writes blocked waiting for a reply to junk")
	}
	select {
	case <-firstReceived:
	case <-time.After(time.Second):
		t.Fatal("active carrier did not receive the complete client stream")
	}
	close(releaseLate)
	reply := make([]byte, 8)
	if _, err := io.ReadFull(c, reply); err != nil || string(reply) != "answered" {
		t.Fatalf("late carrier did not replay junk and handshake: %q, %v", reply, err)
	}
	if _, err := c.Write([]byte("after selection")); err != nil {
		t.Fatal(err)
	}
	reply = make([]byte, len("after selection"))
	if _, err := io.ReadFull(c, reply); err != nil || string(reply) != "after selection" {
		t.Fatalf("winner lost or duplicated data: %q, %v", reply, err)
	}
	// A connected VPN can transfer more than the pre-answer replay limit.
	payload := bytes.Repeat([]byte("ongoing VPN traffic"), 150000)
	go func() { _, err := c.Write(payload); writeDone <- err }()
	reply = make([]byte, len(payload))
	if _, err := io.ReadFull(c, reply); err != nil || !bytes.Equal(reply, payload) {
		t.Fatalf("sustained stream corrupted: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestClosingPendingRaceCancelsBlockedCarrier(t *testing.T) {
	b := testBridge(&dialLog{})
	closed := make(chan struct{})
	opened := make(chan struct{})
	b.candidates = func(string) []wsCarrier {
		return []wsCarrier{{name: "never reads or answers", open: func(ctx context.Context, _, _ string) (net.Conn, error) {
			a, z := net.Pipe()
			close(opened)
			go func() { <-ctx.Done(); _ = z.Close(); close(closed) }()
			return a, nil
		}}}
	}
	c, err := b.Dial(context.Background(), "68.67.118.163", "443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(openvpnReset); err != nil {
		t.Fatal(err)
	}
	select {
	case <-opened:
	case <-time.After(time.Second):
		_ = c.Close()
		t.Fatal("carrier did not open")
	}
	readDone := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); readDone <- err }()
	closeDone := make(chan struct{})
	go func() { _ = c.Close(); close(closeDone) }()
	for _, done := range []<-chan struct{}{closeDone, closed} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("Close did not cancel the pending race")
		}
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("Read succeeded on a closed connection")
		}
	case <-time.After(time.Second):
		t.Fatal("Read stayed blocked after Close")
	}
}

func TestUnansweredRaceBoundsReplayWithoutDroppingBytes(t *testing.T) {
	b := testBridge(&dialLog{}, carrierSpec{name: "silent", silent: true})
	c, err := b.Dial(context.Background(), "68.67.118.163", "443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	payload := bytes.Repeat([]byte{0x55}, 2<<20)
	if n, err := c.Write(payload); err == nil || n == len(payload) {
		t.Fatalf("unanswered race accepted an unbounded prefix: n=%d, err=%v", n, err)
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("replay overflow did not fail the connection")
	}
}

func TestBridgeSendsOnlyOpenVPNToTheRace(t *testing.T) {
	log := &dialLog{}
	b := testBridge(log, carrierSpec{name: "WStunnel a"})
	if got, c := roundTrip(t, b, "api.windscribe.com", []byte{0x16, 0x03, 0x01}); got != "local" {
		t.Fatalf("hostname went to %q", got)
	} else {
		c.Close()
	}
	if got, c := roundTrip(t, b, "68.67.118.163", []byte{0x16, 0x03, 0x01}); got != "local" {
		t.Fatalf("TLS to an IP went to %q", got)
	} else {
		c.Close()
	}
	got, c := roundTrip(t, b, "68.67.118.163", openvpnReset)
	if got != "WStunnel a" {
		t.Fatalf("OpenVPN went to %q", got)
	}
	c.Close()
}

func TestRaceTakesFirstAnswerNotFirstSocket(t *testing.T) {
	log := &dialLog{closed: make(chan string, 8)}
	b := testBridge(log,
		carrierSpec{name: "CDN dead", fail: true},
		carrierSpec{name: "WStunnel silent", silent: true},
		carrierSpec{name: "Stealth slow", delay: 300 * time.Millisecond},
		carrierSpec{name: "Stealth fast"},
	)
	got, c := roundTrip(t, b, "68.67.118.163", openvpnReset)
	if got != "Stealth fast" {
		t.Fatalf("winner %q", got)
	}
	defer c.Close()
	// Every loser that opened a socket is closed; the winner stays open.
	losers := map[string]bool{}
	timeout := time.After(3 * time.Second)
	for len(losers) < 2 {
		select {
		case name := <-log.closed:
			if name == "Stealth fast" {
				t.Fatal("winner was closed")
			}
			losers[name] = true
		case <-timeout:
			t.Fatalf("losers not closed: %v", losers)
		}
	}
}

func TestRaceFailsWhenNothingAnswers(t *testing.T) {
	b := testBridge(&dialLog{}, carrierSpec{name: "a", fail: true}, carrierSpec{name: "b", fail: true})
	if got, _ := roundTrip(t, b, "68.67.118.163", openvpnReset); !strings.Contains(got, "no Windscribe carrier answered") {
		t.Fatalf("got %q", got)
	}
}

func TestRaceOrderLearnsFromStreamLifetime(t *testing.T) {
	b := testBridge(&dialLog{}, carrierSpec{name: "a"}, carrierSpec{name: "b"}, carrierSpec{name: "c"})
	key := "68.67.118.163:443"
	c, done, err := b.race(context.Background(), "68.67.118.163", "443", openvpnReset, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done(2*time.Second, 100) // answered but died at once
	order := b.ordered(key, b.carriersFor("68.67.118.163"))
	if order[len(order)-1].name != "a" {
		t.Fatalf("early death not demoted: %v", order[len(order)-1].name)
	}
	b.mu.Lock()
	b.bad = map[string]map[string]time.Time{}
	b.mu.Unlock()
	b.good[key] = "c"
	if order := b.ordered(key, b.carriersFor("68.67.118.163")); order[0].name != "c" {
		t.Fatalf("working carrier not first: %v", order[0].name)
	}
}

func TestBridgeReportsAnsweredCarrier(t *testing.T) {
	var got []smartproxy.Event
	var mu sync.Mutex
	b := testBridge(&dialLog{}, carrierSpec{name: "WStunnel sni=x"})
	b.report = func(e smartproxy.Event) { mu.Lock(); got = append(got, e); mu.Unlock() }
	_, c := roundTrip(t, b, "68.67.118.163", openvpnReset)
	c.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || !got[0].TCPOnly || got[0].OK || got[0].Path != "WStunnel sni=x" || !isWindscribeCarrier(got[0].Path) {
		t.Fatalf("events %+v", got)
	}
}

func TestDefaultCarriersCoverEveryMethod(t *testing.T) {
	b := newWSBridge(wsOptions{direct: true, sni: "a.example,b.example", cdnHost: "ws.example.com"}, nil, nil, func(string, ...any) {})
	var names []string
	for _, c := range b.carriersFor("68.67.118.163") {
		names = append(names, c.name)
	}
	all := strings.Join(names, "\n")
	for _, want := range []string{"CDN ws.example.com@ws.example.com:443", "WStunnel sni=a.example", "Stealth sni=b.example +anti-DPI", "raw OpenVPN +anti-DPI"} {
		if !strings.Contains(all, want) {
			t.Fatalf("missing %q in\n%s", want, all)
		}
	}
	if len(names) != 2+2*2*2+1 {
		t.Fatalf("%d carriers:\n%s", len(names), all)
	}
}

func TestSniffConnCloseBeforeWriteDoesNotHang(t *testing.T) {
	s := newSniffConn(context.Background(), func(context.Context, []byte, io.Reader) (net.Conn, func(time.Duration, int64), error) {
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
