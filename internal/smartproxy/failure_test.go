package smartproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestFailureClassificationByStage(t *testing.T) {
	for _, c := range []struct {
		err  error
		want FailureKind
	}{
		{&net.OpError{Op: "dial", Err: timeoutErr{}}, KindIPBlock},
		{errors.New("connectex: No connection could be made because the target machine actively refused it."), KindIPBlock},
		{socksReplyError{4}, KindIPBlock},
		{socksReplyError{1}, KindOther},
		{fmt.Errorf("lookup: %w", ErrPoisoned), KindDNSPoison},
		{withKind(KindOther, errors.New("local core refused")), KindOther},
		{context.Canceled, KindNone},
	} {
		if got := classifyConnect(c.err); got != c.want {
			t.Errorf("connect %v: %s, want %s", c.err, got, c.want)
		}
	}
	for _, c := range []struct {
		err   error
		read  int
		first byte
		want  FailureKind
	}{
		{timeoutErr{}, 0, 0, KindSilent},
		{io.EOF, 0, 0, KindReset},
		{errors.New("wsarecv: An existing connection was forcibly closed by the remote host."), 0, 0, KindReset},
		{errors.New("invalid initial TLS handshake record"), 120, 'H', KindBlockPage},
		{timeoutErr{}, 60, 22, KindBlackhole},
		{errors.New("invalid initial TLS handshake record"), 7, 21, KindOther},
	} {
		if got := classifyAfterHello(c.err, c.read, c.first); got != c.want {
			t.Errorf("after hello %v (%d bytes): %s, want %s", c.err, c.read, got, c.want)
		}
	}
	if got := failureKind(fmt.Errorf("route: %w", withKind(KindReset, io.EOF))); got != KindReset {
		t.Fatalf("wrapped kind lost: %s", got)
	}
}

func TestMethodFamilies(t *testing.T) {
	for name, want := range map[string]string{
		"plain: no cutting":                   FamilyPlain,
		"self: SNI split over 2 TCP segments": FamilySplit,
		"self: SNI split over 2 TLS records":  FamilyTLSRec,
		"Zapret2 fake":                        FamilyFake,
		"Xray fragment A":                     FamilySplit,
		"ByeDPI fixed: --oob 1":               FamilyOOB,
	} {
		if got := methodFamily(Upstream{Name: name, Addr: "127.0.0.1:1"}); got != want {
			t.Errorf("%q: %s, want %s", name, got, want)
		}
	}
	if got := methodFamily(Upstream{Name: "Exit: WARP", Exit: true}); got != FamilyExit {
		t.Fatalf("exit: %s", got)
	}
	if got := methodFamily(Upstream{Name: "ByeDPI x", Family: FamilyOOB}); got != FamilyOOB {
		t.Fatalf("explicit family ignored: %s", got)
	}
	if got := ByeDPIFamily([]string{"-s1", "-d", "1", "--ttl", "4"}); got != FamilyFake {
		t.Fatalf("fake must dominate split: %s", got)
	}
	if got := ByeDPIFamily([]string{"-r", "1+s"}); got != FamilyTLSRec {
		t.Fatalf("tlsrec: %s", got)
	}
}

// serve answers every accepted connection with fn after reading the ClientHello.
func serve(t *testing.T, fn func(net.Conn)) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := c.Read(buf); err != nil {
					return
				}
				_ = c.SetReadDeadline(time.Time{})
				fn(c)
			}()
		}
	}()
	return l.Addr().String()
}

func dialTo(addr string, hits *atomic.Int32) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		if hits != nil {
			hits.Add(1)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
}

func TestAttemptFailuresCarryTheirKind(t *testing.T) {
	reset := serve(t, func(c net.Conn) { c.(*net.TCPConn).SetLinger(0) })
	silent := serve(t, func(c net.Conn) { time.Sleep(2 * time.Second) })
	page := serve(t, func(c net.Conn) { _, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\nblocked")) })
	cut := serve(t, func(c net.Conn) { _, _ = c.Write(serverHello[:20]); time.Sleep(2 * time.Second) })
	for addr, want := range map[string]FailureKind{reset: KindReset, silent: KindSilent, page: KindBlockPage, cut: KindBlackhole} {
		p, _ := New(Config{Upstreams: []Upstream{{Name: "plain", Dial: dialTo(addr, nil)}}, FirstByteTimeout: 300 * time.Millisecond})
		_, err := p.attempt(context.Background(), p.ups[0], "site.example", "443", clientHello())
		if got := failureKind(err); got != want {
			t.Errorf("%s: %s (%v), want %s", addr, got, err, want)
		}
		p.recordFailure(p.ups[0], "site.example", "443", err, time.Millisecond)
		if s := p.mem[destinationKey("site.example", "443")].routes["plain"]; s.kind != want {
			t.Errorf("route score kind %s, want %s", s.kind, want)
		}
	}
}

func tcpPair(t *testing.T) (client, proxySide net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); accepted <- c }()
	client, err = net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	proxySide = <-accepted
	t.Cleanup(func() { _ = client.Close(); _ = proxySide.Close() })
	return client, proxySide
}

func TestStallWatchFiresOnlyForSilentYoungFlows(t *testing.T) {
	run := func(server func(net.Conn), client func(net.Conn)) (bool, relayResult) {
		appClient, appSide := tcpPair(t)
		upSide, upServer := tcpPair(t)
		var fired atomic.Bool
		done := make(chan relayResult, 1)
		go func() {
			done <- pipeWatch(appSide, upSide, &stallWatch{after: 150 * time.Millisecond, onStall: func() { fired.Store(true) }})
		}()
		go server(upServer)
		client(appClient)
		time.Sleep(400 * time.Millisecond)
		_ = appClient.Close()
		_ = upServer.Close()
		return fired.Load(), <-done
	}
	// Handshake allowed, then nothing: the client's first flight is never answered.
	fired, r := run(func(net.Conn) {}, func(c net.Conn) { _, _ = c.Write(make([]byte, 64)) })
	if !fired || !r.stalled || r.recovered {
		t.Fatalf("blackhole not detected: fired=%t %+v", fired, r)
	}
	// Nothing at all after the ServerHello while the client waits.
	if fired, _ := run(func(net.Conn) {}, func(net.Conn) {}); !fired {
		t.Fatal("silent server flight not detected")
	}
	// A server that answers the client's first flight is healthy, even if it
	// then stays quiet for long (an idle keep-alive connection).
	echo := func(c net.Conn) {
		_, _ = c.Write([]byte("server flight"))
		buf := make([]byte, 64)
		if n, _ := c.Read(buf); n > 0 {
			_, _ = c.Write([]byte("ticket"))
		}
	}
	if fired, _ := run(echo, func(c net.Conn) { _, _ = c.Write(make([]byte, 64)) }); fired {
		t.Fatal("healthy flow reported as stalled")
	}
	// Slow, not dead: data after the stall marks the result recovered.
	slow := func(c net.Conn) {
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		time.Sleep(250 * time.Millisecond)
		_, _ = c.Write([]byte("late answer"))
	}
	if fired, r := run(slow, func(c net.Conn) { _, _ = c.Write(make([]byte, 64)) }); !fired || !r.recovered {
		t.Fatalf("late answer: fired=%t %+v", fired, r)
	}
}

func TestStalledRelayScoresTheRouteWhileTheConnectionStaysOpen(t *testing.T) {
	// The handshake is allowed through, then the flow is blackholed.
	server := serve(t, func(c net.Conn) {
		_, _ = c.Write(serverHello)
		time.Sleep(3 * time.Second)
	})
	events := make(chan Event, 8)
	p, _ := New(Config{Upstreams: []Upstream{{Name: "plain: no cutting", Dial: dialTo(server, nil)}},
		StallTimeout: 200 * time.Millisecond, OnEvent: func(e Event) { events <- e }})
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Serve(ctx, l)
	c := socksDial(t, l.Addr().String(), "blackhole.example", 443)
	defer c.Close()
	if _, err := c.Write(clientHello()); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, len(serverHello))); err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write(make([]byte, 80)) // Finished and the first request
	deadline := time.After(2 * time.Second)
	for {
		select {
		case e := <-events:
			if !e.Stall {
				continue
			}
			if !e.EarlyClose || e.Failure != KindBlackhole.String() || e.Path != "plain: no cutting" {
				t.Fatalf("stall event: %+v", e)
			}
			p.mu.Lock()
			m := p.mem[destinationKey("blackhole.example", "443")]
			s := m.routes["plain: no cutting"]
			p.mu.Unlock()
			if s.earlyFailures != 1 || s.kind != KindBlackhole || m.kind != KindBlackhole {
				t.Fatalf("score %+v kind %s", *s, m.kind)
			}
			// The client connection was not closed by the proxy.
			_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			if _, err := c.Read(make([]byte, 1)); !isTimeout(err) {
				t.Fatalf("connection should stay open: %v", err)
			}
			return
		case <-deadline:
			t.Fatal("no stall event")
		}
	}
}

func socksDial(t *testing.T, proxy, host string, port int) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte{5, 1, 0})
	if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	req = append(req, byte(port>>8), byte(port))
	_, _ = c.Write(req)
	if _, err := io.ReadFull(c, make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	return c
}

func priorProxy(t *testing.T, cfg Config) *Proxy {
	t.Helper()
	cfg.Upstreams = []Upstream{
		{Name: "plain: no cutting", Rank: 0},
		{Name: "self: SNI split over 2 TLS records", Rank: 1, Send: func(net.Conn, []byte) error { return nil }},
		{Name: "ByeDPI disorder", Rank: 2, Addr: "127.0.0.1:1", Family: FamilyFake},
		{Name: "Exit: WARP", Rank: 5, Addr: "127.0.0.1:2", Exit: true},
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// teach records, on n destinations, that the plain route failed with kind and
// that winner then worked.
func teach(p *Proxy, prefix string, n int, kind FailureKind, losers []int, winner int) {
	for i := range n {
		host := fmt.Sprintf("%s%d.example", prefix, i)
		for _, l := range losers {
			p.recordOutcome(p.ups[l], host, "443", kind, time.Second)
		}
		p.record(p.ups[winner], host, "443", true, 40*time.Millisecond)
		p.record(p.ups[winner], host, "443", true, 40*time.Millisecond) // one destination, one vote
	}
}

func TestNetworkPriorsLearnPerFailureKindAndSummarize(t *testing.T) {
	p := priorProxy(t, Config{})
	teach(p, "sni", 3, KindReset, []int{0, 1}, 2)
	teach(p, "ip", 3, KindIPBlock, []int{0, 1, 2}, 3)
	if got := p.priors[KindReset].wins[FamilyFake]; got != 3 {
		t.Fatalf("fake credited %d times, want once per destination", got)
	}
	if got := p.priorFamily("new.example", "443", KindReset); got != FamilyFake {
		t.Fatalf("SNI reset prior: %q", got)
	}
	if got := p.priorFamily("new.example", "443", KindIPBlock); got != FamilyExit {
		t.Fatalf("IP block prior: %q", got)
	}
	if got := p.priorFamily("new.example", "443", KindSilent); got != "" {
		t.Fatalf("unlearned kind has a prior: %q", got)
	}
	if got := p.priorFamily("sni0.example", "443", KindReset); got != "" {
		t.Fatalf("a destination with its own winner must keep it: %q", got)
	}
	summary := p.FilteringSummary()
	for _, want := range []string{"SNI reset: fake/low-TTL wins (3/3 sites)", "IP block: exit only (3 sites)"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary %q lacks %q", summary, want)
		}
	}
	// Two wins are not yet a lesson; neither is a tie.
	q := priorProxy(t, Config{})
	teach(q, "a", 2, KindReset, []int{0}, 2)
	if got := q.priorFamily("new.example", "443", KindReset); got != "" {
		t.Fatalf("prior after two sites: %q", got)
	}
	teach(q, "b", 3, KindReset, []int{0}, 1)
	if got := q.priorFamily("new.example", "443", KindReset); got != FamilyTLSRec {
		t.Fatalf("leader: %q", got)
	}
	teach(q, "c", 1, KindReset, []int{0}, 2)
	if got := q.priorFamily("new.example", "443", KindReset); got != "" {
		t.Fatalf("tie must not decide: %q", got)
	}
}

func TestPriorOrdersADestinationThatShowedTheSameKind(t *testing.T) {
	p := priorProxy(t, Config{})
	teach(p, "sni", 3, KindReset, []int{0, 1}, 2)
	if first := p.order("fresh.example", "443")[0].Name; first != "plain: no cutting" {
		t.Fatalf("an unknown destination must start plain: %s", first)
	}
	p.recordOutcome(p.ups[0], "fresh.example", "443", KindReset, time.Second)
	if first := p.order("fresh.example", "443")[0].Name; first != "ByeDPI disorder" {
		t.Fatalf("SNI-reset destination should start with the fake family, got %s", first)
	}
}

func TestPriorJumpsTheRaceQueueAfterTheFirstClassifiedFailure(t *testing.T) {
	var resetHits, silentHits, goodHits atomic.Int32
	reset := serve(t, func(c net.Conn) { c.(*net.TCPConn).SetLinger(0) })
	silent := serve(t, func(c net.Conn) { time.Sleep(3 * time.Second) })
	good := serve(t, func(c net.Conn) { _, _ = c.Write(serverHello); time.Sleep(time.Second) })
	p, _ := New(Config{Upstreams: []Upstream{
		{Name: "plain: no cutting", Rank: 0, Dial: dialTo(reset, &resetHits)},
		{Name: "self: SNI split over 2 TCP segments", Rank: 1, Dial: dialTo(silent, &silentHits)},
		{Name: "Zapret2 fake", Rank: 2, Dial: dialTo(good, &goodHits)},
	}, Stagger: 2 * time.Second, MaxParallel: 1, FirstByteTimeout: 2 * time.Second})
	pr := p.priorLocked(KindReset)
	pr.wins[FamilyFake], pr.sites = 4, 4
	began := time.Now()
	w, err := p.race(context.Background(), "prior.example", "443", clientHello())
	if err != nil {
		t.Fatal(err)
	}
	defer w.release()
	if w.path != "Zapret2 fake" || time.Since(began) > time.Second {
		t.Fatalf("won by %s after %v", w.path, time.Since(began))
	}
	if resetHits.Load() != 1 || silentHits.Load() != 0 {
		t.Fatalf("plain %d, split %d attempts", resetHits.Load(), silentHits.Load())
	}
}

func TestFrozenSelectionsIgnorePriors(t *testing.T) {
	p := priorProxy(t, Config{Frozen: &FrozenRoutes{Adaptive: true, Targets: map[string]string{}}})
	pr := p.priorLocked(KindReset)
	pr.wins[FamilyFake], pr.sites = 5, 5
	p.recordOutcome(p.ups[0], "frozen.example", "443", KindReset, time.Second)
	if got := p.priorFamily("frozen.example", "443", KindReset); got != "" {
		t.Fatalf("frozen proxy applied a prior: %q", got)
	}
	if first := p.order("frozen.example", "443")[0].Name; first == "ByeDPI disorder" {
		t.Fatal("frozen order changed by priors")
	}
}

func TestPriorsPersistInTheNetworkHistoryFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "routes.json")
	p := priorProxy(t, Config{HistoryFile: file, HistoryKey: "net-a/balanced"})
	teach(p, "sni", 3, KindReset, []int{0}, 2)
	if err := p.SaveHistory(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(file)
	if !strings.Contains(string(raw), `"sni-reset"`) {
		t.Fatalf("priors not saved: %s", raw)
	}
	q := priorProxy(t, Config{HistoryFile: file, HistoryKey: "net-a/balanced"})
	if got := q.priorFamily("other.example", "443", KindReset); got != FamilyFake {
		t.Fatalf("reloaded prior: %q", got)
	}
	if got, want := HistorySummary(file, "net-a/balanced"), p.FilteringSummary(); got != want || got == "" {
		t.Fatalf("history summary %q, live %q", got, want)
	}
	// A reloaded destination does not vote twice.
	q.record(q.ups[2], "sni0.example", "443", true, time.Millisecond)
	if got := q.priors[KindReset].wins[FamilyFake]; got != 3 {
		t.Fatalf("restored destination re-credited: %d", got)
	}
	if HistorySummary(file, "net-b/balanced") != "" {
		t.Fatal("another network's priors leaked")
	}
	r := priorProxy(t, Config{HistoryFile: file, HistoryKey: "net-b/balanced"})
	if r.FilteringSummary() != "" {
		t.Fatal("another network loaded these priors")
	}
}

func TestSeedsOrderTheFirstRaceOnlyUntilLiveResultsArrive(t *testing.T) {
	p, _ := New(Config{Upstreams: []Upstream{{Name: "plain: no cutting"}, {Name: "ByeDPI split"}, {Name: "Zapret2 fake"}},
		Seeds: map[string]string{"Tested.Example:443": "Zapret2 fake", "site.example:443": "ByeDPI split"}, SeedDefault: "ByeDPI split"})
	if first := p.order("tested.example", "443")[0].Name; first != "Zapret2 fake" {
		t.Fatalf("exact seed ignored: %s", first)
	}
	if first := p.order("cdn.site.example", "443")[0].Name; first != "ByeDPI split" {
		t.Fatalf("site seed ignored: %s", first)
	}
	if first := p.order("other.example", "443")[0].Name; first != "ByeDPI split" {
		t.Fatalf("default seed ignored: %s", first)
	}
	// The seeded method failed live: it no longer leads.
	p.record(p.ups[2], "tested.example", "443", false, time.Second)
	p.record(p.ups[2], "tested.example", "443", false, time.Second)
	if first := p.order("tested.example", "443")[0].Name; first == "Zapret2 fake" {
		t.Fatal("a failing seed stayed first")
	}
}

func TestRefusedTakeoverWithdrawsItsPriorCredit(t *testing.T) {
	p, _ := New(Config{Upstreams: []Upstream{{Name: "plain: no cutting"},
		{Name: "Front", Takeover: func(context.Context, string, string, []byte) (Session, error) { return nil, errors.New("unused") }}}})
	p.recordOutcome(p.ups[0], "video.example", "443", KindReset, time.Second)
	p.record(p.ups[1], "video.example", "443", true, time.Millisecond)
	if p.priors[KindReset].wins[FamilyFront] != 1 {
		t.Fatal("prepared takeover not credited")
	}
	p.rejectTakeover("video.example", "443", "Front")
	if pr := p.priors[KindReset]; pr.wins[FamilyFront] != 0 || pr.losses[FamilyFront] != 1 {
		t.Fatalf("refused takeover still counted as a win: %+v", *pr)
	}
}
