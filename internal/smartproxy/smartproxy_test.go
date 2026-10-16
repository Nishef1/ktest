package smartproxy

import (
	"bytes"
	"context"
	"fmt"
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

func TestFirstFlightReadsTLSHeaderSplitAcrossWrites(t *testing.T) {
	for split := 1; split < 5; split++ {
		t.Run(fmt.Sprint(split), func(t *testing.T) {
			a, z := net.Pipe()
			defer a.Close()
			defer z.Close()
			want := clientHello()
			written := make(chan error, 1)
			go func() {
				_ = z.SetWriteDeadline(time.Now().Add(time.Second))
				if _, err := z.Write(want[:split]); err != nil {
					written <- err
					return
				}
				_, err := z.Write(want[split:])
				written <- err
			}()
			got := readFirstFlight(a)
			if !bytes.Equal(got, want) || !isTLSFlight(got) {
				t.Fatalf("partial TLS record escaped classification: got %x, want %x", got, want)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStoppingProxyClosesActiveSOCKSTunnel(t *testing.T) {
	for _, shutdown := range []string{"context", "listener"} {
		t.Run(shutdown, func(t *testing.T) {
			dest, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer dest.Close()
			remoteClosed := make(chan struct{})
			go func() {
				defer close(remoteClosed)
				c, err := dest.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
			p, err := New(Config{Upstreams: PlainUpstreams()})
			if err != nil {
				t.Fatal(err)
			}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			finished := make(chan error, 1)
			go func() { finished <- p.Serve(ctx, l) }()
			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			host, port, _ := net.SplitHostPort(dest.Addr().String())
			if err := socksConnect(c, host, port); err != nil {
				t.Fatal(err)
			}
			_, _ = c.Write([]byte{1, 2})
			if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
				t.Fatal(err)
			}
			if shutdown == "context" {
				cancel()
			} else {
				_ = l.Close()
			}
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("SOCKS listener did not stop")
			}
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			_, err = c.Read(make([]byte, 1))
			if err == nil {
				t.Fatal("tunnel remained readable after shutdown")
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("SOCKS tunnel remained open after shutdown")
			}
			select {
			case <-remoteClosed:
			case <-time.After(time.Second):
				t.Fatal("upstream remained open after shutdown")
			}
		})
	}
}

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
	p, addr := startProxy(t, []Upstream{{Name: "blocked", Addr: blocked}, {Name: "good", Addr: good}})
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
	_, addr := startProxy(t, []Upstream{{Name: "a", Addr: fakeSocks(t, dest, false, &h1)}, {Name: "b", Addr: fakeSocks(t, dest, false, &h2)}})
	_, port, _ := net.SplitHostPort(dest)
	if got := viaProxy(t, addr, "site.example", port, clientHello()); len(got) != 0 {
		t.Fatalf("unexpected data %x", got)
	}
}

func TestNonTLSTrafficUsesBestPathWithoutRacing(t *testing.T) {
	dest := destination(t)
	var hits atomic.Int32
	_, addr := startProxy(t, []Upstream{{Name: "only", Addr: fakeSocks(t, dest, true, &hits)}})
	_, port, _ := net.SplitHostPort(dest)
	if got := viaProxy(t, addr, "plain.example", port, []byte("GET / HTTP/1.1\r\n\r\n")); !bytes.Equal(got, serverHello) {
		t.Fatalf("got %x", got)
	}
}

func TestUpstreamValidationAndTLSDetection(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("empty upstream list accepted")
	}
	if _, err := New(Config{Upstreams: []Upstream{{Name: "a", Addr: "x"}, {Name: "a", Addr: "y"}}}); err == nil {
		t.Fatal("duplicate names accepted")
	}
	if !isTLSFlight(clientHello()) || isTLSFlight([]byte("GET / HTTP/1.1")) || isTLSFlight(nil) {
		t.Fatal("TLS flight detection wrong")
	}
}

func TestLocalDNSUpstreamGetsResolvedIPWhileOthersGetTheName(t *testing.T) {
	dest := destination(t)
	_, port, _ := net.SplitHostPort(dest)
	seen := make(chan string, 4)
	capture := func(name string) string {
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
					host, _, err := socksRequest(c)
					if err != nil {
						return
					}
					seen <- name + "=" + host
					_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
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
	resolver := func(_ context.Context, host string) ([]string, error) { return []string{"203.0.113.9"}, nil }
	for _, tc := range []struct {
		up   Upstream
		want string
	}{
		{Upstream{Name: "bye", LocalDNS: true}, "bye=203.0.113.9"},
		{Upstream{Name: "xray"}, "xray=poisoned.example"},
	} {
		tc.up.Addr = capture(tc.up.Name)
		p, err := New(Config{Upstreams: []Upstream{tc.up}, Resolve: resolver, FirstByteTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		ctx, cancel := context.WithCancel(context.Background())
		go p.Serve(ctx, l)
		viaProxy(t, l.Addr().String(), "poisoned.example", port, clientHello())
		cancel()
		select {
		case got := <-seen:
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("upstream never contacted")
		}
	}
}

func TestSiteKeyGroupsNodesOfOneService(t *testing.T) {
	for in, want := range map[string]string{
		"r1---sn-abc.googlevideo.com": "googlevideo.com",
		"www.youtube.com":             "youtube.com",
		"youtube.com":                 "youtube.com",
		"bbc.co.uk":                   "bbc.co.uk",
		"www.bbc.co.uk":               "bbc.co.uk",
		"142.250.1.1":                 "142.250.1.1",
		"WWW.Example.ORG.":            "example.org",
	} {
		if got := siteKey(in); got != want {
			t.Errorf("siteKey(%q)=%q want %q", in, got, want)
		}
	}
}

func TestMemoryIsSharedAcrossHostsOfOneSiteAndEventsReportTheWinner(t *testing.T) {
	dest := destination(t)
	_, port, _ := net.SplitHostPort(dest)
	var h1, h2 atomic.Int32
	events := make(chan Event, 8)
	p, err := New(Config{
		Upstreams:        []Upstream{{Name: "blocked", Addr: fakeSocks(t, dest, false, &h1)}, {Name: "good", Addr: fakeSocks(t, dest, true, &h2)}},
		Stagger:          50 * time.Millisecond,
		FirstByteTimeout: 600 * time.Millisecond,
		OnEvent:          func(e Event) { events <- e },
	})
	if err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Serve(ctx, l)

	if got := viaProxy(t, l.Addr().String(), "r1.cdn.example.com", port, clientHello()); !bytes.Equal(got, serverHello) {
		t.Fatalf("got %x", got)
	}
	e := <-events
	if !e.OK || e.Path != "good" || e.Site != "example.com" {
		t.Fatalf("event %+v", e)
	}
	// A different host of the same site starts with the remembered winner.
	if !p.hasMemory("r2.cdn.example.com") {
		t.Fatal("memory should be shared by every host of the site")
	}
}

func TestSecondWaveStartsEveryRemainingPathAtOnce(t *testing.T) {
	dest := destination(t)
	_, port, _ := net.SplitHostPort(dest)
	var hits [5]atomic.Int32
	var ups []Upstream
	for i := 0; i < 4; i++ {
		ups = append(ups, Upstream{Name: fmt.Sprintf("dead%d", i), Addr: fakeSocks(t, dest, false, &hits[i])})
	}
	ups = append(ups, Upstream{Name: "good", Addr: fakeSocks(t, dest, true, &hits[4])})
	// One-by-one staggering with this stagger would need 4 * 2s before "good".
	p, err := New(Config{Upstreams: ups, Stagger: 2 * time.Second, FirstByteTimeout: 1500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Serve(ctx, l)
	began := time.Now()
	if got := viaProxy(t, l.Addr().String(), "site.example", port, clientHello()); !bytes.Equal(got, serverHello) {
		t.Fatalf("got %x", got)
	}
	if took := time.Since(began); took > 3500*time.Millisecond {
		t.Fatalf("took %s: the second wave must not be staggered one path at a time", took)
	}
}

func TestOrderPrefersPlainWhenTrackRecordsAreEqualAndDemotesFailingPaths(t *testing.T) {
	p, err := New(Config{Upstreams: []Upstream{
		{Name: "cut", Addr: "x", Rank: 3},
		{Name: "external", Addr: "y", Rank: 2},
		{Name: "plain", Rank: 0},
	}})
	if err != nil {
		t.Fatal(err)
	}
	names := func() []string {
		var out []string
		for _, u := range p.order("site.example") {
			out = append(out, u.Name)
		}
		return out
	}
	if got := names(); got[0] != "plain" || got[1] != "external" || got[2] != "cut" {
		t.Fatalf("static rank order wrong: %v", got)
	}
	// Equal success rates must not let an early winner run away with the order.
	p.record(p.ups[0], "a.example", true, 10*time.Millisecond)
	p.record(p.ups[2], "a.example", true, 10*time.Millisecond)
	if got := names(); got[0] != "plain" {
		t.Fatalf("a single win must not outrank plain: %v", got)
	}
	// A path that keeps failing sinks below the others.
	for i := 0; i < 6; i++ {
		p.record(p.ups[2], "b.example", false, time.Second)
	}
	if got := names(); got[len(got)-1] != "plain" {
		t.Fatalf("failing plain path should rank last: %v", got)
	}
}

func TestSoftResolveFallsBackToTheNameWhereHardResolveSkipsThePath(t *testing.T) {
	dest := destination(t)
	_, port, _ := net.SplitHostPort(dest)
	seen := make(chan string, 4)
	capture := func() string {
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
					host, _, err := socksRequest(c)
					if err != nil {
						return
					}
					seen <- host
					_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
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
	poisoned := func(context.Context, string) ([]string, error) { return nil, ErrPoisoned }
	run := func(u Upstream) []byte {
		u.Addr = capture()
		p, err := New(Config{Upstreams: []Upstream{u}, Resolve: poisoned, FirstByteTimeout: 500 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go p.Serve(ctx, l)
		return viaProxy(t, l.Addr().String(), "blocked.example", port, clientHello())
	}
	if got := run(Upstream{Name: "soft", LocalDNS: true, SoftResolve: true}); !bytes.Equal(got, serverHello) {
		t.Fatalf("soft path should still connect by name, got %x", got)
	}
	if h := <-seen; h != "blocked.example" {
		t.Fatalf("soft path received %q, want the name", h)
	}
	if got := run(Upstream{Name: "hard", LocalDNS: true}); len(got) != 0 {
		t.Fatalf("hard path must not connect to a poisoned name, got %x", got)
	}
	select {
	case h := <-seen:
		t.Fatalf("hard path contacted its upstream with %q", h)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestNonTLSUsesOnlyDirectAndExitPathsAndRemembersBlockedDestinations(t *testing.T) {
	dest := destination(t)
	var cutHits, exitHits atomic.Int32
	// A cutting path cannot help a protocol it cannot parse: it must stay unused.
	cutting := Upstream{Name: "cut", Addr: fakeSocks(t, dest, true, &cutHits), Rank: 2}
	p, addr := startProxy(t, []Upstream{{Name: "plain", Rank: 0}, cutting})
	// An exit that joins while the proxy runs.
	if err := p.Add(Upstream{Name: "exit", Addr: fakeSocks(t, dest, true, &exitHits), Rank: 5, Exit: true}); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(Upstream{Name: "exit", Addr: "127.0.0.1:1"}); err == nil {
		t.Fatal("duplicate name accepted")
	}
	// A destination that refuses direct connections, as one blocked by address does.
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()
	host, port, _ := net.SplitHostPort(deadAddr)
	for i := 0; i < 3; i++ {
		if got := viaProxy(t, addr, host, port, []byte("hello")); !bytes.Equal(got, serverHello) {
			t.Fatalf("attempt %d: got %x", i, got)
		}
	}
	if cutHits.Load() != 0 {
		t.Fatalf("a cutting path carried non-TLS traffic (%d)", cutHits.Load())
	}
	if exitHits.Load() != 3 {
		t.Fatalf("exit carried %d of 3 connections", exitHits.Load())
	}
	// After the first failure the direct route is no longer tried first.
	st := p.Stats()
	for _, s := range st {
		if s.Name == "plain" && s.Failures != 1 {
			t.Fatalf("direct failed %d times, want exactly 1 (then remembered)", s.Failures)
		}
	}
}

func TestLatePathIsALastResortNotACompetitor(t *testing.T) {
	dest := destination(t)
	var good, late atomic.Int32
	_, addr := startProxy(t, []Upstream{
		{Name: "good", Addr: fakeSocks(t, dest, true, &good), Rank: 1},
		{Name: "late", Addr: fakeSocks(t, dest, true, &late), Rank: 0, Late: true}, // outranks it, yet must wait
	})
	_, port, _ := net.SplitHostPort(dest)
	for i := 0; i < 3; i++ {
		if got := viaProxy(t, addr, "site.example", port, clientHello()); !bytes.Equal(got, serverHello) {
			t.Fatalf("got %x", got)
		}
	}
	if late.Load() != 0 {
		t.Fatalf("the late path competed %d times although a good path answered", late.Load())
	}

	// When every other path fails, it is tried at once, without waiting for the gate.
	var bad, last atomic.Int32
	_, addr2 := startProxy(t, []Upstream{
		{Name: "bad", Addr: fakeSocks(t, dest, false, &bad), Rank: 1},
		{Name: "late", Addr: fakeSocks(t, dest, true, &last), Rank: 5, Late: true},
	})
	began := time.Now()
	if got := viaProxy(t, addr2, "blocked.example", port, clientHello()); !bytes.Equal(got, serverHello) {
		t.Fatalf("got %x", got)
	}
	if took := time.Since(began); took > 2*time.Second || last.Load() != 1 {
		t.Fatalf("last resort took %v, used %d times", took, last.Load())
	}
}

func TestNonTLSFirstFlightIsOfferedToTheExitWhenTheDirectRouteOpensButStaysSilent(t *testing.T) {
	// A filter that lets the TCP handshake through and drops the protocol's
	// first bytes: the connection opens and nothing ever comes back.
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { silent.Close() })
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, c) }()
		}
	}()
	dest := destination(t)
	var hits atomic.Int32
	p, addr := startProxy(t, []Upstream{{Name: "plain", Rank: 0}})
	if err := p.Add(Upstream{Name: "exit", Addr: fakeSocks(t, dest, true, &hits), Rank: 5, Exit: true}); err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(silent.Addr().String())
	for i := 0; i < 2; i++ {
		if got := viaProxy(t, addr, host, port, []byte("mtproto-init")); !bytes.Equal(got, serverHello) {
			t.Fatalf("attempt %d: got %x", i, got)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("the exit carried %d of 2 connections", hits.Load())
	}
	if w := p.Winners()[host]; w != "exit" {
		t.Fatalf("remembered %q for %s, want exit", w, host)
	}
}
