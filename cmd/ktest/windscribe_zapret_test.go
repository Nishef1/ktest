package main

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/packetdesync"
)

func TestZapretFollowsWindscribeConnectTarget(t *testing.T) {
	var starts, stops atomic.Int32
	b := newWSBridge(wsOptions{direct: true, sni: "www.speedtest.net", zapret: "fake"}, nil, nil, func(string, ...any) {})
	b.catalog = newWSNodeCatalog()
	b.catalog.lists["global"] = wsCatalogList{Fetched: time.Now(), nodes: map[string]wsNode{
		"203.0.113.10": {TCP: "203.0.113.10", IP: "203.0.113.11", Hostname: "one.windscribe.com"},
		"203.0.113.20": {TCP: "203.0.113.20", IP: "203.0.113.21", Hostname: "two.windscribe.com"},
	}}
	var selected string
	b.packet = &wsPacketDesync{gate: make(chan struct{}, 1), start: func(_ context.Context, ip string) (func() error, error) {
		selected = ip
		starts.Add(1)
		return func() error { stops.Add(1); return nil }, nil
	}}
	b.candidates = func(host string) []wsCarrier {
		entry := b.catalog.endpoints(host)[0].ip
		return []wsCarrier{{name: "WStunnel test", addr: net.JoinHostPort(entry, "443"), open: func(context.Context, string, string) (net.Conn, error) {
			if selected != entry || starts.Load() != stops.Load()+1 {
				return nil, errors.New("TLS opened before the matching packet filter")
			}
			return fakeServer(entry, 0, false, nil), nil
		}}}
	}
	for _, target := range []string{"203.0.113.10", "203.0.113.20"} {
		label, conn := roundTrip(t, b, target, []byte{0, 42, 0x38, 1})
		if conn == nil {
			t.Fatal(label)
		}
		if label != b.catalog.endpoints(target)[0].ip || starts.Load() != stops.Load() {
			t.Fatalf("wrong node or filter survived outer handshake: label=%s starts=%d stops=%d", label, starts.Load(), stops.Load())
		}
		conn.Close()
	}
	if starts.Load() != 2 {
		t.Fatalf("did not follow both Connect targets: %d", starts.Load())
	}
}

func TestZapretSerializesFiltersAndStopsOnCanceledHandshake(t *testing.T) {
	var active atomic.Int32
	p := &wsPacketDesync{gate: make(chan struct{}, 1), start: func(context.Context, string) (func() error, error) {
		if active.Add(1) != 1 {
			t.Error("overlapping packet filters")
		}
		return func() error { active.Add(-1); return nil }, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	entered, finished := make(chan struct{}), make(chan error, 1)
	go func() {
		_, err := p.open(ctx, "203.0.113.11", func() (net.Conn, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		})
		finished <- err
	}()
	<-entered
	waitCtx, stopWait := context.WithCancel(context.Background())
	stopWait()
	if _, err := p.open(waitCtx, "203.0.113.21", func() (net.Conn, error) {
		t.Error("canceled contender opened TLS")
		return nil, nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting cancellation: %v", err)
	}
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if active.Load() != 0 {
		t.Fatal("canceled handshake left its filter active")
	}
}

func TestZapretConcurrentHandshakesNeverOverlapFilters(t *testing.T) {
	var active atomic.Int32
	p := &wsPacketDesync{gate: make(chan struct{}, 1), start: func(context.Context, string) (func() error, error) {
		if active.Add(1) != 1 {
			t.Error("overlapping native filters")
		}
		return func() error { active.Add(-1); return nil }, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	firstEntered, releaseFirst := make(chan struct{}), make(chan struct{})
	finished := make(chan error, 2)
	go func() {
		_, err := p.open(ctx, "203.0.113.11", func() (net.Conn, error) {
			close(firstEntered)
			select {
			case <-releaseFirst:
			case <-ctx.Done():
			}
			return nil, errors.New("first handshake failed")
		})
		finished <- err
	}()
	<-firstEntered
	go func() {
		_, err := p.open(ctx, "203.0.113.21", func() (net.Conn, error) { return nil, nil })
		finished <- err
	}()
	close(releaseFirst)
	for range 2 {
		<-finished
	}
	if active.Load() != 0 {
		t.Fatal("native filter leaked")
	}
}

func TestZapretCarrierInventoryDoesNotStackLocalShaping(t *testing.T) {
	b := newWSBridge(wsOptions{direct: true, sni: "www.speedtest.net", zapret: "fake"}, nil, nil, func(string, ...any) {})
	b.catalog = newWSNodeCatalog()
	b.catalog.lists["global"] = wsCatalogList{Fetched: time.Now(), nodes: map[string]wsNode{
		"203.0.113.10": {TCP: "203.0.113.10", IP: "203.0.113.11", IP3: "203.0.113.12", Hostname: "one.windscribe.com"},
	}}
	carriers := b.carriersFor("203.0.113.10")
	if len(carriers) == 0 {
		t.Fatal("no automatically discovered WStunnel carriers")
	}
	for _, carrier := range carriers {
		if !strings.HasPrefix(carrier.name, "WStunnel ") || carrier.method != "Zapret2 fake" {
			t.Fatalf("unshaped or stacked carrier in Zapret2 selection: %+v", carrier)
		}
	}
}

func TestZapretCleanupFailureBlocksNextFilter(t *testing.T) {
	var starts int
	p := &wsPacketDesync{gate: make(chan struct{}, 1), start: func(context.Context, string) (func() error, error) {
		starts++
		return func() error { return errors.New("cleanup unconfirmed") }, nil
	}}
	client, server := net.Pipe()
	defer server.Close()
	if conn, err := p.open(context.Background(), "203.0.113.11", func() (net.Conn, error) { return client, nil }); err == nil || conn != nil {
		t.Fatal("unconfirmed filter cleanup accepted as prepared transport")
	}
	if _, err := client.Write([]byte{1}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("carrier not closed: %v", err)
	}
	_, err := p.open(context.Background(), "203.0.113.21", func() (net.Conn, error) { t.Fatal("opened after cleanup failure"); return nil, nil })
	if err == nil || starts != 1 {
		t.Fatalf("started another filter after cleanup failure: %d, %v", starts, err)
	}
}

func TestZapretCanceledStartupDoesNotPoisonNextConnect(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "canceled", true: "deadline"}[timeout], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if timeout {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
			}
			defer cancel()
			starts := 0
			p := &wsPacketDesync{gate: make(chan struct{}, 1), start: func(context.Context, string) (func() error, error) {
				starts++
				if starts == 1 {
					if !timeout {
						cancel()
					}
					<-ctx.Done()
					return nil, ctx.Err() // native startup confirmed its process was reaped
				}
				return func() error { return nil }, nil
			}}
			if _, err := p.open(ctx, "203.0.113.11", func() (net.Conn, error) { t.Fatal("TLS after canceled startup"); return nil, nil }); !errors.Is(err, ctx.Err()) {
				t.Fatalf("startup cancellation lost: %v", err)
			}
			client, server := net.Pipe()
			defer server.Close()
			conn, err := p.open(context.Background(), "203.0.113.21", func() (net.Conn, error) { return client, nil })
			defer client.Close()
			if err != nil || conn == nil || starts != 2 {
				t.Fatalf("canceled attempt poisoned the next CONNECT: starts=%d, err=%v", starts, err)
			}
		})
	}
}

func TestZapretControllerFailureDoesNotExhaustRemoteCarriers(t *testing.T) {
	b := newWSBridge(wsOptions{direct: true, zapret: "fake"}, nil, nil, func(string, ...any) {})
	b.catalog = newWSNodeCatalog()
	b.catalog.lists["global"] = wsCatalogList{Fetched: time.Now(), nodes: map[string]wsNode{
		"203.0.113.10": {TCP: "203.0.113.10", IP: "203.0.113.11", Hostname: "one.windscribe.com"},
	}}
	var starts atomic.Int32
	b.packet = &wsPacketDesync{gate: make(chan struct{}, 1), start: func(context.Context, string) (func() error, error) {
		starts.Add(1)
		return nil, errors.New("local driver unavailable")
	}}
	b.candidates = func(string) []wsCarrier {
		var carriers []wsCarrier
		for _, name := range []string{"WStunnel one", "WStunnel two", "WStunnel three"} {
			carriers = append(carriers, wsCarrier{name: name, addr: "203.0.113.11:443", open: func(context.Context, string, string) (net.Conn, error) {
				t.Error("remote carrier opened without its controller")
				return nil, nil
			}})
		}
		return carriers
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, err := b.race(ctx, "203.0.113.10", "443", []byte{0, 42, 0x38}, nil)
	if err == nil || !strings.Contains(err.Error(), "local driver unavailable") {
		t.Fatalf("lost controller failure: %v", err)
	}
	snapshot := b.progressSnapshot("203.0.113.10:443")
	if snapshot.failed != 0 || snapshot.tried != 0 || snapshot.remaining != 3 || snapshot.cooling != 0 {
		t.Fatalf("local controller failure counted as remote transport failures: %+v", snapshot)
	}
	if starts.Load() != 1 {
		t.Fatalf("native driver restarted %d times", starts.Load())
	}
}

func TestZapretCanceledStartupStillBlocksWhenCleanupIsUnconfirmed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	starts := 0
	p := &wsPacketDesync{gate: make(chan struct{}, 1), start: func(context.Context, string) (func() error, error) {
		starts++
		cancel()
		return nil, errors.Join(ctx.Err(), packetdesync.ErrCleanupUnconfirmed)
	}}
	open := func() (net.Conn, error) { t.Fatal("unsafe native cleanup allowed a transport"); return nil, nil }
	if _, err := p.open(ctx, "203.0.113.11", open); !errors.Is(err, packetdesync.ErrCleanupUnconfirmed) {
		t.Fatal(err)
	}
	if _, err := p.open(context.Background(), "203.0.113.21", open); !errors.Is(err, packetdesync.ErrCleanupUnconfirmed) || starts != 1 {
		t.Fatalf("unconfirmed cancellation permitted another native filter: starts=%d, err=%v", starts, err)
	}
}

func TestZapretWaitForControllerDoesNotCountAsTCPFailure(t *testing.T) {
	b := newWSBridge(wsOptions{direct: true, zapret: "fake"}, nil, nil, func(string, ...any) {})
	b.replyTimeout = time.Millisecond
	b.catalog = newWSNodeCatalog()
	b.catalog.lists["global"] = wsCatalogList{Fetched: time.Now(), nodes: map[string]wsNode{
		"203.0.113.10": {TCP: "203.0.113.10", IP: "203.0.113.11", Hostname: "one.windscribe.com"},
	}}
	b.packet = &wsPacketDesync{gate: make(chan struct{}, 1), start: func(context.Context, string) (func() error, error) {
		t.Error("waiting contender started another controller")
		return nil, errors.New("unexpected startup")
	}}
	b.packet.gate <- struct{}{} // another CONNECT owns the controller
	defer func() { <-b.packet.gate }()
	b.candidates = func(string) []wsCarrier {
		return []wsCarrier{{name: "WStunnel waiting", addr: "203.0.113.11:443", open: func(context.Context, string, string) (net.Conn, error) {
			t.Error("transport opened without controller admission")
			return nil, nil
		}}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, _ = b.race(ctx, "203.0.113.10", "443", []byte{0, 42, 0x38}, nil)
	snapshot := b.progressSnapshot("203.0.113.10:443")
	if snapshot.failed != 0 || snapshot.tried != 0 || snapshot.remaining != 1 || snapshot.cooling != 0 {
		t.Fatalf("controller admission timeout counted as a tested TCP path: %+v", snapshot)
	}
}

func TestZapretRefusesUnverifiedEntryAndKeepsAPIOffPacketPath(t *testing.T) {
	b := newWSBridge(wsOptions{zapret: "fake"}, func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("API local route") }, nil, func(string, ...any) {})
	b.packet = &wsPacketDesync{gate: make(chan struct{}, 1), start: func(context.Context, string) (func() error, error) {
		t.Fatal("unverified packet target")
		return nil, nil
	}}
	_, err := b.openCarrier(context.Background(), "203.0.113.10", "443", wsCarrier{addr: "203.0.113.11:443"})
	if err == nil {
		t.Fatal("unverified endpoint accepted")
	}
	_, err = b.Dial(context.Background(), "api.windscribe.com", "443")
	if err == nil || !strings.Contains(err.Error(), "API local route") {
		t.Fatalf("API bypassed its existing dialer: %v", err)
	}
}

func TestZapretConnectOptionsRejectOtherRoutes(t *testing.T) {
	for _, change := range []func(*connectOptions){
		func(o *connectOptions) { o.mode = ModeWindscribeAether },
		func(o *connectOptions) { o.mode = ModeFast },
		func(o *connectOptions) { o.tun = true },
		func(o *connectOptions) { o.ws.direct = false },
		func(o *connectOptions) { o.ws.serverIP = "203.0.113.11" },
		func(o *connectOptions) { o.ws.cdnHost = "own.example.com" },
		func(o *connectOptions) { o.ws.zapret = "arbitrary" },
	} {
		o := optionsForMode(defaultConnectOptions("test"), ModeWindscribe)
		o.ws.zapret = "fake"
		change(&o)
		if err := validateConnectOptions(o); err == nil {
			t.Fatalf("unsafe Zapret combination accepted: %+v", o)
		}
	}
	for _, mode := range []ConnectionMode{ModeFast, ModeWindscribeAether} {
		o := defaultConnectOptions("test")
		o.ws.zapret = "fake"
		if optionsForMode(o, mode).ws.packetEnabled() {
			t.Fatalf("saved Zapret leaked into %s", mode)
		}
	}
}
