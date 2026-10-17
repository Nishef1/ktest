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
	if len(cs) != 1 || cs[0].name != "raw OpenVPN +anti-DPI" {
		t.Fatalf("unknown node must keep only its original raw destination; got %+v", cs)
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
	b.catalog = newWSNodeCatalog()
	if err := b.catalog.replace("global", []byte(`{"data":[{"nodes":[{"ip":"68.67.118.162","ip2":"68.67.118.163","ip3":"68.67.118.164","hostname":"se.example.com"}]}]}`), time.Now()); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range b.carriersFor("68.67.118.163") {
		names = append(names, c.name)
	}
	all := strings.Join(names, "\n")
	for _, want := range []string{"CDN ws.example.com entry=ws.example.com:443", "WStunnel sni=a.example", "Stealth sni=b.example +anti-DPI", "raw OpenVPN +anti-DPI"} {
		if !strings.Contains(all, want) {
			t.Fatalf("missing %q in\n%s", want, all)
		}
	}
	if len(names) != 2+2*2*(2+1)*2+1 {
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

func TestWindscribeCarrierRetriesExploreOtherIPAndWrapper(t *testing.T) {
	b := newWSBridge(wsOptions{}, nil, nil, func(string, ...any) {})
	key := "152.233.50.130:443"
	cs := []wsCarrier{
		{name: "WStunnel sni=a entry=152.233.50.178"},
		{name: "WStunnel sni=b entry=152.233.50.146"},
		{name: "WStunnel sni=c entry=152.233.50.130"},
		{name: "Stealth sni=a entry=152.233.50.178"},
		{name: "Stealth sni=b entry=152.233.50.146"},
		{name: "raw OpenVPN +anti-DPI"},
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

func TestAmbiguousConcurrentWindscribeSessionsAreNotPromoted(t *testing.T) {
	b := newWSBridge(wsOptions{}, nil, nil, func(string, ...any) {})
	first := &wsActiveCarrier{key: "one:443", name: "WStunnel first"}
	second := &wsActiveCarrier{key: "two:443", name: "Stealth second"}
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
	if n := attempted.Load(); n != 24 {
		t.Fatalf("unbounded carrier race: attempted %d of 80, want 24", n)
	}
	// A second call advances the rotation rather than launching the same
	// first candidate from the provider's list every time.
	first := b.ordered("68.67.118.163:443", b.carriersFor("68.67.118.163"))[0].name
	second := b.ordered("68.67.118.163:443", b.carriersFor("68.67.118.163"))[0].name
	if first == second {
		t.Fatalf("retries did not explore new SNI/IP candidates: %q", first)
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
