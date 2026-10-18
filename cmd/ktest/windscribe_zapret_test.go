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
