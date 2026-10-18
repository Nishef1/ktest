package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
	"github.com/Nishef1/ktest/internal/wstunnel"
)

func TestUnknownWindscribeNodeDoesNotInventNeighbourAddresses(t *testing.T) {
	b := newWSBridge(wsOptions{direct: true, sni: "www.speedtest.net"}, nil, nil, func(string, ...any) {})
	cs := b.carriersFor("203.0.113.101")
	if len(cs) != 0 {
		t.Fatalf("unknown node must not invent neighbors or fall back to raw OpenVPN: %+v", cs)
	}
}

func TestExplicitWStunnelOverrideDoesNotInventStealth(t *testing.T) {
	b := newWSBridge(wsOptions{direct: true, sni: "www.speedtest.net", serverIP: "203.0.113.9"}, nil, nil, func(string, ...any) {})
	for _, c := range b.carriersFor("203.0.113.101") {
		if strings.HasPrefix(c.name, "Stealth ") || (strings.HasPrefix(c.name, "WStunnel ") && c.addr != "203.0.113.9:443") {
			t.Fatalf("invalid override route: %+v", c)
		}
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
	// The currently published provider node list also uses this domain.
	current := &x509.Certificate{Subject: pkix.Name{CommonName: "us-central-154.whiskergalaxy.com"}}
	if err := windscribeServerCert([]*x509.Certificate{current}); err != nil {
		t.Fatalf("current provider hostname refused: %v", err)
	}
	for _, domain := range []string{"windscribe.com.evil.example", "whiskergalaxy.com.evil.example", "whiskergalaxy.com"} {
		other := &x509.Certificate{Subject: pkix.Name{CommonName: domain}}
		if windscribeServerCert([]*x509.Certificate{other}) == nil {
			t.Fatalf("unrecognized outer server identity accepted: %s", domain)
		}
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
		if _, err := b.Write(serverControlPacket(label)); err != nil {
			return
		}
		_, _ = b.Read(buf) // keep the stream open until closed
	}()
	return a
}

type carrierSpec struct {
	name   string
	method string
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
			cs = append(cs, wsCarrier{name: s.name, method: s.method, open: func(ctx context.Context, host, port string) (net.Conn, error) {
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

// serverControlPacket supplies realistic server framing for race tests. The
// label sits in the opaque payload, which is left for Windscribe to verify.
func serverControlPacket(label string) []byte {
	packet := append([]byte{0, 0, 0x40}, make([]byte, 13)...)
	packet = append(packet, label...)
	binary.BigEndian.PutUint16(packet[:2], uint16(len(packet)-2))
	return packet
}

// roundTrip writes first and returns the label in the carrier's reply.
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
	var header [2]byte
	_, err = io.ReadFull(c, header[:])
	if err != nil {
		c.Close()
		return "error: " + err.Error(), nil
	}
	buf := make([]byte, int(binary.BigEndian.Uint16(header[:])))
	if _, err := io.ReadFull(c, buf); err != nil {
		c.Close()
		return "error: " + err.Error(), nil
	}
	return string(buf[14:]), c
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
					if _, err := z.Write(serverControlPacket("answered")); err == nil {
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
	reply := make([]byte, len(serverControlPacket("answered")))
	if _, err := io.ReadFull(c, reply); err != nil || !bytes.Equal(reply, serverControlPacket("answered")) {
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

func TestBridgeRecognisesFragmentedAPIWithoutChangingBytes(t *testing.T) {
	for _, payload := range [][]byte{
		{0x16, 0x03, 0x01, 0, 3, 1, 2, 3},
		[]byte("GET / HTTP/1.1\r\n\r\n"),
		[]byte("POST / HTTP/1.1\r\n\r\n"),
		[]byte("OPTIONS / HTTP/1.1\r\n\r\n"),
		[]byte("PATCH / HTTP/1.1\r\n\r\n"),
	} {
		t.Run(fmt.Sprintf("prefix_%x", payload[:2]), func(t *testing.T) {
			b := testBridge(&dialLog{}) // no OpenVPN candidates: misrouting must fail
			b.local = func(context.Context, string, string) (net.Conn, error) {
				a, z := net.Pipe()
				go func() {
					defer z.Close()
					got := make([]byte, len(payload))
					if _, err := io.ReadFull(z, got); err == nil {
						_, _ = z.Write(got)
					}
					_, _ = io.Copy(io.Discard, z)
				}()
				return a, nil
			}
			c, err := b.Dial(context.Background(), "203.0.113.9", "443")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			written := make(chan error, 1)
			go func() {
				for _, v := range payload {
					if _, err := c.Write([]byte{v}); err != nil {
						written <- err
						return
					}
				}
				written <- nil
			}()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(c, got); err != nil {
				t.Fatalf("fragmented API was not carried: %v", err)
			}
			if err := <-written; err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("API stream changed: got %x, write error %v", got, err)
			}
		})
	}
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

// A TLS listener speaking HTTP is reachable, but cannot carry OpenVPN.
// Also exercise TCP segmentation: an incomplete valid header must not win.
func TestRaceRejectsHTTPAndIncompleteOpenVPNBeforeSelectingCompleteReply(t *testing.T) {
	b := testBridge(&dialLog{})
	packet := append([]byte{0, 14, 0x40}, make([]byte, 13)...)
	b.candidates = func(string) []wsCarrier {
		var cs []wsCarrier
		for _, reply := range [][]byte{[]byte("HTTP/1.1 501 Not Implemented\r\n\r\n"), packet[:3], packet} {
			cs = append(cs, wsCarrier{name: "probe", open: func(ctx context.Context, _, _ string) (net.Conn, error) {
				a, z := net.Pipe()
				go func() {
					defer z.Close()
					if _, err := io.ReadFull(z, make([]byte, len(openvpnReset))); err != nil {
						return
					}
					// First byte arrives by itself, as it can on a TCP stream.
					if _, err := z.Write(reply[:1]); err != nil {
						return
					}
					if _, err := z.Write(reply[1:]); err != nil {
						return
					}
					_, _ = io.Copy(z, z)
				}()
				return a, nil
			}})
		}
		return cs
	}
	c, _, err := b.race(context.Background(), "203.0.113.100", "443", openvpnReset, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, len(packet))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, packet) {
		t.Fatalf("race selected HTTP/incomplete data or lost the valid prefix: %x err=%v", got, err)
	}
}

func TestInitialOpenVPNReplyRejectsClientAndDataPackets(t *testing.T) {
	for _, opcode := range []byte{7, 10, 11, 6, 9} {
		packet := serverControlPacket("opaque")
		packet[2] = opcode << 3
		if _, err := readOpenVPNReply(bytes.NewReader(packet)); err == nil {
			t.Fatalf("client/data opcode %d selected as an initial server reply", opcode)
		}
	}
}

func TestRaceFailsWhenNothingAnswers(t *testing.T) {
	b := testBridge(&dialLog{}, carrierSpec{name: "a", fail: true}, carrierSpec{name: "b", fail: true})
	if got, _ := roundTrip(t, b, "68.67.118.163", openvpnReset); !strings.Contains(got, "no Windscribe carrier answered") {
		t.Fatalf("got %q", got)
	}
}

func TestRaceReportsEachFailureBoundary(t *testing.T) {
	b := testBridge(&dialLog{})
	b.candidates = func(string) []wsCarrier {
		var cs []wsCarrier
		for _, stage := range []string{"tcp", "tls", "websocket"} {
			cs = append(cs, wsCarrier{name: stage, addr: "203.0.113.9:443", source: "global/ip", open: func(context.Context, string, string) (net.Conn, error) {
				return nil, &wstunnel.StageError{Stage: stage, Err: errors.New("probe failure")}
			}})
		}
		cs = append(cs, wsCarrier{name: "no VPN response", open: func(context.Context, string, string) (net.Conn, error) {
			a, z := net.Pipe()
			_ = z.Close()
			return a, nil
		}})
		return cs
	}
	var events []smartproxy.Event
	b.report = func(e smartproxy.Event) { events = append(events, e) }
	_, _, err := b.race(context.Background(), "203.0.113.100", "443", openvpnReset, nil)
	if err == nil || len(events) != 1 {
		t.Fatalf("missing race failure: events=%+v err=%v", events, err)
	}
	for _, stage := range []string{"tcp=1", "tls=1", "websocket=1", "openvpn=1"} {
		if !strings.Contains(events[0].Err, stage) {
			t.Fatalf("missing %s in %+v", stage, events[0])
		}
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
	for _, candidate := range order {
		if candidate.name == "a" {
			t.Fatal("failed handshake still races against fresh alternatives")
		}
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
	b.catalog = newWSNodeCatalog()
	if err := b.catalog.replace("global", []byte(`{"data":[{"nodes":[{"ip":"68.67.118.162","ip2":"68.67.118.163","ip3":"68.67.118.164","hostname":"se.example.com"}]}]}`), time.Now()); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range b.carriersFor("68.67.118.163") {
		names = append(names, c.name)
	}
	all := strings.Join(names, "\n")
	for _, want := range []string{"CDN ws.example.com entry=ws.example.com:443", "WStunnel sni=a.example", "Stealth sni=b.example +anti-DPI"} {
		if !strings.Contains(all, want) {
			t.Fatalf("missing %q in\n%s", want, all)
		}
	}
	if len(names) != 2+2*2*(2+1)*2 {
		t.Fatalf("%d carriers:\n%s", len(names), all)
	}
	if strings.Contains(all, "raw OpenVPN") {
		t.Fatalf("raw OpenVPN must never be included in automatic carrier discovery: %s", all)
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

// An inventory with nineteen variants per method must launch one from each
// method in the first pass, then the next variant of each method, and so on.
// The first 64 slots may not be monopolized by the first few method families.
func TestWindscribeHeavyMethodsLeadButRoundRobinRemainsFair(t *testing.T) {
	// The setup deliberately begins with the lightest methods. Sorting by
	// their actual technique must take precedence over the inventory order.
	candidates := []wsCarrier{
		{name: "WStunnel light A", method: "direct"},
		{name: "WStunnel plain-first", method: "ByeDPI adaptive (plain first, slices only after a reset)"},
		{name: "WStunnel tls", method: "ByeDPI TLS record slicing"},
		{name: "WStunnel combo A", method: "ByeDPI disorder + fake packet"},
		{name: "Stealth combo B", method: "ByeDPI split + disorder (Windows default)"},
		{name: "Stealth fake", method: "ByeDPI fake packet, low TTL"},
	}
	for _, method := range []string{"direct", "ByeDPI TLS record slicing", "ByeDPI disorder + fake packet"} {
		candidates = append(candidates, wsCarrier{name: "WStunnel second " + method, method: method})
	}
	for attempt := uint64(0); attempt < 8; attempt++ {
		ordered := wsDiversify(candidates, attempt)
		if len(ordered) != len(candidates) {
			t.Fatalf("lost method variants: %d", len(ordered))
		}
		firstRound := ordered[:6]
		seen := map[string]bool{}
		lastTier := -1
		for _, c := range firstRound {
			tier := wsMethodPriority(c.method)
			if tier < lastTier {
				t.Fatalf("heavy-to-light order broken: %+v", firstRound)
			}
			lastTier = tier
			if seen[c.method] {
				t.Fatalf("method repeated before all had one attempt: %+v", firstRound)
			}
			seen[c.method] = true
		}
		if wsMethodPriority(firstRound[0].method) != 0 || firstRound[len(firstRound)-1].method != "direct" {
			t.Fatalf("first attempt must start with composites, and unconfirmed baseline be last: %+v", firstRound)
		}
	}
}

func TestWindscribeRealCarriersExcludeRawAcrossAllWrappers(t *testing.T) {
	b := newWSBridge(wsOptions{direct: true, sni: "www.speedtest.net", cdnHost: "ws.example.com"}, nil, nil, func(string, ...any) {})
	b.methods = func() []smartproxy.WindscribeMethod {
		return []smartproxy.WindscribeMethod{
			{Name: "ByeDPI disorder + fake packet"},
			{Name: "Xray local TCP fragment B"},
			{Name: "self: TLS records and TCP segments", TLSOnly: true},
		}
	}
	b.catalog = newWSNodeCatalog()
	if err := b.catalog.replace("global", []byte(`{"data":[{"nodes":[{"ip":"192.0.2.10","ip2":"203.0.113.12","ip3":"192.0.2.11","hostname":"node.example.com"}]}]}`), time.Now()); err != nil {
		t.Fatal(err)
	}
	cs := b.carriersFor("203.0.113.12")
	if len(cs) == 0 {
		t.Fatal("wrapped carriers vanished")
	}
	methods := map[string]bool{}
	for _, c := range cs {
		if strings.HasPrefix(c.name, "raw OpenVPN") {
			t.Fatalf("a raw OpenVPN carrier remains: %+v", c)
		}
		methods[c.method] = true
	}
	for _, name := range []string{"direct", "ByeDPI disorder + fake packet", "Xray local TCP fragment B", "self: TLS records and TCP segments"} {
		if !methods[name] {
			t.Fatalf("lost wrapped technique %q", name)
		}
	}
}

func TestWindscribeRoundRobinOnePerMethodBeforeRepeats(t *testing.T) {
	var candidates []wsCarrier
	for method := range 15 {
		for variant := range 19 {
			name := fmt.Sprintf("WStunnel sni=s%d entry=192.0.2.%d hello=chrome", variant%3, variant+1)
			candidates = append(candidates, wsCarrier{
				name:   fmt.Sprintf("%s m%d v%d", name, method, variant),
				method: fmt.Sprintf("method-%02d", method),
			})
		}
	}
	for attempt := uint64(0); attempt < 15; attempt++ {
		ranked := wsDiversify(candidates, attempt)
		if len(ranked) != len(candidates) {
			t.Fatalf("lost variants: got %d, want %d", len(ranked), len(candidates))
		}
		for start := 0; start < 15*3; start += 15 {
			seen := map[string]bool{}
			for _, c := range ranked[start : start+15] {
				if seen[c.method] {
					t.Fatalf("attempt %d round %d repeats %s before other methods", attempt, start/15, c.method)
				}
				seen[c.method] = true
			}
			if len(seen) != 15 {
				t.Fatalf("attempt %d round %d covered only %d of 15 methods", attempt, start/15, len(seen))
			}
		}
		first64 := map[string]int{}
		for _, c := range ranked[:64] {
			first64[c.method]++
		}
		for method := range 15 {
			key := fmt.Sprintf("method-%02d", method)
			if first64[key] < 4 {
				t.Fatalf("attempt %d starved %s in 64-candidate budget: %v", attempt, key, first64)
			}
		}
	}
}

// Prior failed variants must not make a method disappear from the first pass.
// Within that method, its next untried candidate takes priority.
func TestWindscribeUntriedPriorityIsPerMethodNotWholeInventory(t *testing.T) {
	b := newWSBridge(wsOptions{}, nil, nil, func(string, ...any) {})
	key := "203.0.113.100:443"
	var cs []wsCarrier
	for method := range 4 {
		for variant := range 3 {
			cs = append(cs, wsCarrier{
				name:   fmt.Sprintf("WStunnel sni=a method%d variant%d", method, variant),
				method: fmt.Sprintf("method-%d", method),
			})
		}
	}
	b.registerCarriers(key, "203.0.113.100", cs)
	for _, c := range cs {
		if c.method == "method-0" && strings.HasSuffix(c.name, "variant0") {
			b.carrierProgress(key, c.name, "start")
			b.carrierProgress(key, c.name, "tls: reset")
			b.carrierProgress(key, c.name, "finish")
		}
	}
	ordered := b.ordered(key, cs)
	seen := map[string]bool{}
	for _, c := range ordered[:4] {
		if seen[c.method] {
			t.Fatalf("method duplicated before all four were sampled: %+v", ordered[:4])
		}
		seen[c.method] = true
		if c.method == "method-0" && strings.HasSuffix(c.name, "variant0") {
			t.Fatal("failed variant was selected ahead of the other two untried variants")
		}
	}
}

// Confirmed paths still get their exclusive retry before the fair rotation.
func TestWindscribeConfirmedCarrierRemainsFirstWithMethodRoundRobin(t *testing.T) {
	b := newWSBridge(wsOptions{}, nil, nil, func(string, ...any) {})
	key := "203.0.113.100:443"
	cs := []wsCarrier{
		{name: "WStunnel preferred", method: "method-A"},
		{name: "WStunnel alternative", method: "method-A"},
		{name: "Stealth backup", method: "method-B"},
	}
	b.registerCarriers(key, "203.0.113.100", cs)
	b.good[key] = cs[0].name
	if got := b.ordered(key, cs)[0].name; got != cs[0].name {
		t.Fatalf("confirmed carrier lost priority: %q", got)
	}
}

func TestWindscribeCarrierRetriesExploreOtherIPAndWrapper(t *testing.T) {
	b := newWSBridge(wsOptions{}, nil, nil, func(string, ...any) {})
	key := "152.233.50.130:443"
	cs := []wsCarrier{
		{name: "WStunnel sni=a entry=152.233.50.178"},
		{name: "WStunnel sni=b entry=152.233.50.146"},
		{name: "WStunnel sni=c entry=152.233.50.130"},
		{name: "Stealth sni=a entry=152.233.50.178"},
		{name: "Stealth sni=b entry=152.233.50.146"},
	}
	first := make(map[string]bool)
	for range 4 {
		ordered := b.ordered(key, cs)
		if len(ordered) != len(cs) {
			t.Fatalf("lost candidates after scheduling: %d", len(ordered))
		}
		seen := map[string]bool{}
		for _, candidate := range ordered {
			if seen[candidate.name] {
				t.Fatalf("duplicate candidate %s", candidate.name)
			}
			seen[candidate.name] = true
		}
		if wsCarrierFamily(ordered[0].name) == wsCarrierFamily(ordered[1].name) {
			t.Fatalf("one transport monopolizes the first two launch slots: %+v", ordered[:2])
		}
		first[ordered[0].name] = true
	}
	if len(first) < 2 {
		t.Fatalf("retries chose the same entry first: %+v", first)
	}
}

func TestWindscribeTransportFailureHasTemporaryCooldown(t *testing.T) {
	b := newWSBridge(wsOptions{}, nil, nil, func(string, ...any) {})
	key := "152.233.50.130:443"
	cs := []wsCarrier{{name: "WStunnel failed"}, {name: "Stealth other"}}
	b.good[key] = "WStunnel failed"
	b.demoteFailure(key, "WStunnel failed", "tls")
	ordered := b.ordered(key, cs)
	if ordered[0].name != "Stealth other" {
		t.Fatalf("failed TLS candidate still wins priority: %+v", ordered)
	}
	if remaining := time.Until(b.bad[key]["WStunnel failed"]); remaining <= 0 || remaining > time.Minute {
		t.Fatalf("bad cooldown: %v", remaining)
	}
	b.bad[key]["WStunnel failed"] = time.Now().Add(-time.Second)
	b.good[key] = "WStunnel failed"
	if next := b.ordered(key, cs); next[0].name != "WStunnel failed" {
		t.Fatalf("cooldown incorrectly became a permanent block: %+v", next)
	}
}

func TestWindscribeOnlyLearnsCLIAuthenticatedSingleCarrier(t *testing.T) {
	b := testBridge(&dialLog{}, carrierSpec{name: "Stealth a"})
	key := "68.67.118.163:443"
	reply, done, err := b.race(context.Background(), "68.67.118.163", "443", openvpnReset, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Close()
	done(2*time.Minute, 128<<10)
	if b.good[key] != "" {
		t.Fatal("long-lived OpenVPN-shaped traffic was mistaken for authenticated Windscribe")
	}
	reply, done, err = b.race(context.Background(), "68.67.118.163", "443", openvpnReset, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Close()
	b.observeCLIConnected()
	done(2*time.Minute, 128<<10)
	if b.good[key] != "Stealth a" {
		t.Fatalf("CLI-authenticated stable carrier not remembered: %q", b.good[key])
	}
}

func TestWindscribeCLIConnectedWithoutKtestCarrierIsNotAttributed(t *testing.T) {
	var output bytes.Buffer
	b := newWSBridge(wsOptions{}, nil, nil, func(string, ...any) {})
	b.view = &wsProgressView{t: plainTerm(&output)}
	b.observeCLIConnected()
	if len(b.confirmations) != 0 || len(b.good) != 0 {
		t.Fatal("Windscribe CLI status alone was credited to a nonexistent ktest carrier")
	}
	if !strings.Contains(output.String(), "ktest did not carry a verifiable VPN") {
		t.Fatalf("missing nonattribution warning: %s", output.String())
	}
}

func TestAmbiguousConcurrentWindscribeSessionsAreNotPromoted(t *testing.T) {
	b := newWSBridge(wsOptions{}, nil, nil, func(string, ...any) {})
	first := &wsActiveCarrier{key: "one:443", name: "WStunnel first", started: time.Now()}
	second := &wsActiveCarrier{key: "two:443", name: "Stealth second", started: time.Now()}
	b.active[first] = true
	b.active[second] = true
	b.observeCLIConnected()
	if first.confirmed || second.confirmed {
		t.Fatal("ambiguous concurrent sessions were credited with one CLI status")
	}
	delete(b.active, second)
	b.observeCLIConnected()
	if !first.confirmed || second.confirmed {
		t.Fatal("single active carrier was not attributed correctly")
	}
}

func TestWindscribeRaceCapsCandidateCountWhileRotatingRetries(t *testing.T) {
	b := testBridge(&dialLog{})
	var attempted atomic.Int32
	b.stagger = time.Millisecond
	b.candidates = func(string) []wsCarrier {
		var cs []wsCarrier
		for i := range 80 {
			n := i
			cs = append(cs, wsCarrier{
				name: fmt.Sprintf("WStunnel index=%d", i),
				open: func(ctx context.Context, _, _ string) (net.Conn, error) {
					attempted.Add(1)
					return nil, errors.New(fmt.Sprintf("failed-%d", n))
				},
			})
		}
		return cs
	}
	_, _, _ = b.race(context.Background(), "68.67.118.163", "443", openvpnReset, nil)
	if n := attempted.Load(); n != 64 {
		t.Fatalf("unbounded carrier race: attempted %d of 80, want 64", n)
	}
	// A second call advances the rotation rather than launching the same
	// first candidate from the provider's list every time.
	first := b.ordered("68.67.118.163:443", b.carriersFor("68.67.118.163"))[0].name
	second := b.ordered("68.67.118.163:443", b.carriersFor("68.67.118.163"))[0].name
	if first == second {
		t.Fatalf("retries did not explore new SNI/IP candidates: %q", first)
	}
}

// Fast failures should refill the queue within one Windscribe CONNECT,
// without exceeding the outer-socket concurrency limit.
func TestWindscribeRaceRefillsBoundedParallelQueue(t *testing.T) {
	b := testBridge(&dialLog{})
	b.stagger = time.Millisecond
	var active, peak, attempted atomic.Int32
	b.candidates = func(string) []wsCarrier {
		var cs []wsCarrier
		for i := range 80 {
			cs = append(cs, wsCarrier{
				name: fmt.Sprintf("WStunnel index=%d", i),
				open: func(ctx context.Context, _, _ string) (net.Conn, error) {
					attempted.Add(1)
					n := active.Add(1)
					for {
						old := peak.Load()
						if n <= old || peak.CompareAndSwap(old, n) {
							break
						}
					}
					defer active.Add(-1)
					select {
					case <-time.After(8 * time.Millisecond):
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					return nil, errors.New("simulated TLS failure")
				},
			})
		}
		return cs
	}
	_, _, _ = b.race(context.Background(), "68.67.118.163", "443", openvpnReset, nil)
	if attempted.Load() != 64 || peak.Load() > 16 || peak.Load() < 2 {
		t.Fatalf("queue did not refill with bounded parallelism: attempted=%d peak=%d", attempted.Load(), peak.Load())
	}
}

func TestConfirmedWindscribeTCPPromotesEvenShortRealSession(t *testing.T) {
	b := testBridge(&dialLog{}, carrierSpec{name: "WStunnel verified"})
	key := "68.67.118.163:443"
	c, done, err := b.race(context.Background(), "68.67.118.163", "443", openvpnReset, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b.observeCLIConnected()
	if got := b.good[key]; got != "WStunnel verified" {
		t.Fatalf("real CLI Connected transition was not learned: %q", got)
	}
	done(4*time.Second, 1024)
	if b.good[key] != "WStunnel verified" || !b.bad[key]["WStunnel verified"].IsZero() {
		t.Fatal("confirmed short session was incorrectly treated as a DPI failure")
	}
}

func TestUnconfirmedWindscribeHandshakeTimeoutDemotesBriefly(t *testing.T) {
	b := testBridge(&dialLog{}, carrierSpec{name: "Stealth uncertain"})
	key := "68.67.118.163:443"
	c, done, err := b.race(context.Background(), "68.67.118.163", "443", openvpnReset, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done(24*time.Second, 1024)
	delay := time.Until(b.bad[key]["Stealth uncertain"])
	if delay < 75*time.Second || delay > 100*time.Second {
		t.Fatalf("24-second unverified stream was not temporarily deprioritized: %v", delay)
	}
}

func TestWindscribeCarrierReportsUnexpectedUpstreamEOFOnce(t *testing.T) {
	a, peer := net.Pipe()
	defer a.Close()
	var logs []string
	c := &carrierConn{
		Conn:        a,
		cancel:      func() {},
		stopClose:   func() bool { return true },
		name:        "Stealth entry=198.51.100.4",
		destination: "203.0.113.2:443",
		started:     time.Now(),
		logf: func(format string, args ...any) {
			logs = append(logs, fmt.Sprintf(format, args...))
		},
	}
	_ = peer.Close()
	buf := make([]byte, 8)
	_, _ = c.Read(buf)
	_, _ = c.Read(buf)
	if len(logs) != 1 || !strings.Contains(logs[0], "source of closure unverified") {
		t.Fatalf("EOF must be observed once without incorrectly blaming DPI: %v", logs)
	}
	_ = c.Close()
	_, _ = c.Read(buf)
	if len(logs) != 1 {
		t.Fatalf("local shutdown was misreported as upstream failure: %v", logs)
	}
}

func TestWindscribeCarrierOffersUpstreamHelloWithoutReplacingChrome(t *testing.T) {
	b := newWSBridge(wsOptions{direct: true, sni: "example.com"}, nil, nil, func(string, ...any) {})
	b.catalog = newWSNodeCatalog()
	if err := b.catalog.replace("global", []byte(`{"data":[{"nodes":[{"ip":"192.0.2.10","ip2":"203.0.113.12","ip3":"192.0.2.11","hostname":"node.example.com"}]}]}`), time.Now()); err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool)
	for _, c := range b.carriersFor("203.0.113.12") {
		names[c.name] = true
	}
	for _, want := range []string{
		"WStunnel sni=example.com entry=192.0.2.10 hello=chrome",
		"WStunnel sni=example.com entry=192.0.2.10 hello=windscribe",
		"Stealth sni=example.com entry=192.0.2.11 hello=chrome",
		"Stealth sni=example.com entry=192.0.2.11 hello=windscribe",
	} {
		if !names[want] {
			t.Fatalf("fingerprint fallback profile missing: %q", want)
		}
	}
}

func TestWindscribeSNIFairnessUnderCandidateBudget(t *testing.T) {
	var candidates []wsCarrier
	for _, sni := range []string{"one.test", "two.test", "three.test"} {
		for i := 0; i < 30; i++ {
			candidates = append(candidates, wsCarrier{name: fmt.Sprintf("WStunnel sni=%s entry=%d hello=chrome", sni, i)})
		}
	}
	for attempt := uint64(0); attempt < 4; attempt++ {
		ordered := wsDiversify(candidates, attempt)
		seen := make(map[string]int)
		for _, candidate := range ordered[:24] {
			for _, sni := range []string{"one.test", "two.test", "three.test"} {
				if strings.Contains(candidate.name, "sni="+sni) {
					seen[sni]++
				}
			}
		}
		for _, sni := range []string{"one.test", "two.test", "three.test"} {
			if seen[sni] != 8 {
				t.Fatalf("attempt %d starved SNI %s with %d/24 entries: %+v", attempt, sni, seen[sni], seen)
			}
		}
	}
}

func TestShortCLIConnectedSessionNeedsRepeatedUnexpectedUpstreamEndForCooldown(t *testing.T) {
	b := testBridge(&dialLog{}, carrierSpec{name: "WStunnel selected"})
	key := "68.67.118.163:443"
	for i := 0; i < 2; i++ {
		conn, done, err := b.race(context.Background(), "68.67.118.163", "443", openvpnReset, nil)
		if err != nil {
			t.Fatal(err)
		}
		b.observeCLIConnected()
		b.mu.Lock()
		for session := range b.active {
			session.upstreamEnd = true
		}
		b.mu.Unlock()
		done(3*time.Second, 1024)
		_ = conn.Close()
		if i == 0 && b.good[key] != "WStunnel selected" {
			t.Fatal("single short EOF incorrectly erased successful carrier")
		}
	}
	if b.good[key] != "" || time.Until(b.bad[key]["WStunnel selected"]) < 60*time.Second {
		t.Fatal("repeated unexpected upstream ends did not temporarily demote the unstable carrier")
	}
}

func TestStaleCarrierCannotBeCreditedWithNewCLIConnection(t *testing.T) {
	b := newWSBridge(wsOptions{}, nil, nil, func(string, ...any) {})
	s := &wsActiveCarrier{key: "test:443", name: "old", started: time.Now().Add(-3 * time.Minute)}
	b.active[s] = true
	b.observeCLIConnected()
	if s.confirmed || b.good[s.key] != "" {
		t.Fatal("old unrelated carrier falsely credited with newer CLI Connected state")
	}
}

func TestFailedHandshakeCannotWinTheNextRaceWithAnotherFastReset(t *testing.T) {
	b := testBridge(&dialLog{})
	b.candidates = func(string) []wsCarrier {
		return []wsCarrier{
			{name: "WStunnel fast reset", open: func(context.Context, string, string) (net.Conn, error) {
				a, peer := net.Pipe()
				go func() {
					defer peer.Close()
					packet := make([]byte, len(openvpnReset))
					if _, err := io.ReadFull(peer, packet); err == nil {
						_, _ = peer.Write(serverControlPacket("reset"))
					}
					// Upstream closes after its initial control reply, before
					// Windscribe could complete TLS/authentication.
				}()
				return a, nil
			}},
			{name: "Stealth viable", open: func(context.Context, string, string) (net.Conn, error) {
				return fakeServer("viable", 60*time.Millisecond, false, nil), nil
			}},
		}
	}
	label, conn := roundTrip(t, b, "68.67.118.163", openvpnReset)
	if conn == nil {
		t.Fatalf("initial reply failed: %q", label)
	}
	var one [1]byte
	if _, err := conn.Read(one[:]); err != io.EOF {
		conn.Close()
		t.Fatalf("expected the reproduced upstream close, got %v", err)
	}
	// EOF from the bridge follows session cleanup, so the next real Dial
	// observes the failed handshake without calling its scoring hook here.
	_ = conn.Close()
	label, next := roundTrip(t, b, "68.67.118.163", openvpnReset)
	if next != nil {
		defer next.Close()
	}
	if label != "viable" {
		t.Fatalf("failed handshake stole the retry from a slower alternative: %q", label)
	}
}

func TestUnconfirmedWindscribeMethodYieldsAcrossVariants(t *testing.T) {
	for _, session := range []struct {
		name     string
		lived    time.Duration
		received int64
	}{
		{"handshake timeout", 24 * time.Second, 284},
		{"long unverified stream", time.Minute, 128 << 10},
	} {
		t.Run(session.name, func(t *testing.T) {
			b := testBridge(&dialLog{},
				carrierSpec{name: "WStunnel fake A", method: "ByeDPI disorder + fake packet"},
				carrierSpec{name: "WStunnel fake B", method: "ByeDPI disorder + fake packet"},
				carrierSpec{name: "WStunnel slower", method: "ByeDPI TLS record slicing", delay: 60 * time.Millisecond},
			)
			host := "68.67.118.163"
			first, done, err := b.race(context.Background(), host, "443", openvpnReset, nil)
			if err != nil {
				t.Fatal(err)
			}
			if first.(*carrierConn).name == "WStunnel slower" {
				t.Fatal("fixture did not reproduce the faster unconfirmed reply")
			}
			done(session.lived, session.received)
			_ = first.Close()

			next, done, err := b.race(context.Background(), host, "443", openvpnReset, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer next.Close()
			if got := next.(*carrierConn).name; got != "WStunnel slower" {
				t.Fatalf("another variant of the unconfirmed method stole the retry: %s", got)
			}
			b.observeCLIConnected()
			done(time.Second, 1024)
			_ = next.Close()
			// A CLI-confirmed method overrides trial counts, even though a
			// quicker method has another unused entry/SNI variant.
			confirmed, done, err := b.race(context.Background(), host, "443", openvpnReset, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer confirmed.Close()
			if got := confirmed.(*carrierConn).name; got != "WStunnel slower" {
				t.Fatalf("confirmed carrier lost priority: %s", got)
			}
			done(time.Second, 1024)

			// This target's trials must not bias another IP's first attempt.
			other, done, err := b.race(context.Background(), "68.67.118.164", "443", openvpnReset, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			if other.(*carrierConn).name == "WStunnel slower" {
				t.Fatal("another target inherited method trial history")
			}
			done(time.Second, 1024)
		})
	}
}

func TestWindscribeMethodRoundsFallBackWhenAlternativesFail(t *testing.T) {
	b := testBridge(&dialLog{},
		carrierSpec{name: "WStunnel fast A", method: "ByeDPI disorder + fake packet"},
		carrierSpec{name: "WStunnel fast B", method: "ByeDPI disorder + fake packet"},
		carrierSpec{name: "WStunnel blocked", method: "ByeDPI TLS record slicing", fail: true},
	)
	for attempt := range 2 {
		conn, done, err := b.race(context.Background(), "68.67.118.163", "443", openvpnReset, nil)
		if err != nil {
			t.Fatalf("attempt %d could not recover through the previously selected method: %v", attempt, err)
		}
		done(24*time.Second, 284)
		_ = conn.Close()
	}
}

func TestCLIConfirmedCarrierIsNotPreemptedByAnUnverifiedFastReply(t *testing.T) {
	b := testBridge(&dialLog{}, carrierSpec{name: "WStunnel verified", delay: 60 * time.Millisecond}, carrierSpec{name: "Stealth reset only"})
	b.good["68.67.118.163:443"] = "WStunnel verified"
	label, conn := roundTrip(t, b, "68.67.118.163", openvpnReset)
	if conn != nil {
		defer conn.Close()
	}
	if label != "WStunnel verified" {
		t.Fatalf("unverified reply replaced a CLI-confirmed carrier: %q", label)
	}
}

func TestAllCoolingCarriersReprobeOnlyTheEarliestExpiry(t *testing.T) {
	b := newWSBridge(wsOptions{}, nil, nil, func(string, ...any) {})
	key := "68.67.118.163:443"
	b.bad[key] = map[string]time.Time{"recent": time.Now().Add(time.Minute), "oldest": time.Now().Add(20 * time.Second)}
	got := b.ordered(key, []wsCarrier{{name: "recent"}, {name: "oldest"}})
	if len(got) != 1 || got[0].name != "oldest" {
		t.Fatalf("all-cooling retry must remain possible without racing every failed route: %+v", got)
	}
}

func TestEndedCarrierCannotBePromotedByALaterCLIObservation(t *testing.T) {
	b := newWSBridge(wsOptions{}, nil, nil, func(string, ...any) {})
	s := &wsActiveCarrier{key: "68.67.118.163:443", name: "ended", started: time.Now(), upstreamEnd: true}
	b.active[s] = true
	b.observeCLIConnected()
	if s.confirmed || b.good[s.key] != "" {
		t.Fatal("CLI observation promoted a carrier whose upstream already ended")
	}
}

func TestSilentPreferredCarrierTimesOutAndFallsBackInTheSameAttempt(t *testing.T) {
	b := testBridge(&dialLog{}, carrierSpec{name: "WStunnel was working", silent: true}, carrierSpec{name: "Stealth fallback"})
	b.replyTimeout = 30 * time.Millisecond
	key := "68.67.118.163:443"
	b.good[key] = "WStunnel was working"
	label, conn := roundTrip(t, b, "68.67.118.163", openvpnReset)
	if conn != nil {
		defer conn.Close()
	}
	if label != "Stealth fallback" {
		t.Fatalf("silent preferred carrier prevented fallback: %q", label)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.good[key] != "" || !b.bad[key]["WStunnel was working"].After(time.Now()) {
		t.Fatal("silent preferred route was not demoted after its own reply deadline")
	}
}

func TestInitialReplyDeadlineDoesNotExpireTheSelectedVPNStream(t *testing.T) {
	b := testBridge(&dialLog{})
	b.replyTimeout = 40 * time.Millisecond
	b.candidates = func(string) []wsCarrier {
		return []wsCarrier{{name: "WStunnel echo", open: func(context.Context, string, string) (net.Conn, error) {
			a, peer := net.Pipe()
			go func() {
				defer peer.Close()
				packet := make([]byte, len(openvpnReset))
				if _, err := io.ReadFull(peer, packet); err == nil {
					_, _ = peer.Write(serverControlPacket("echo"))
					_, _ = io.Copy(peer, peer)
				}
			}()
			return a, nil
		}}}
	}
	label, conn := roundTrip(t, b, "68.67.118.163", openvpnReset)
	if conn == nil {
		t.Fatalf("initial reply failed: %q", label)
	}
	defer conn.Close()
	time.Sleep(2 * b.replyTimeout)
	if _, err := conn.Write([]byte("VPN data")); err != nil {
		t.Fatalf("selected stream expired with the initial-reply deadline: %v", err)
	}
	buf := make([]byte, len("VPN data"))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "VPN data" {
		t.Fatalf("stream lost continuation data: %q, %v", buf, err)
	}
}
