package smartproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestRouteHistorySurvivesRestartWithoutAuthorizingAnExit(t *testing.T) {
	file := filepath.Join(t.TempDir(), "routes.json")
	cfg := Config{HistoryFile: file, HistoryKey: "wifi/fast", Upstreams: []Upstream{{Name: "plain"}, {Name: "ByeDPI split", Rank: 2}, {Name: "exit", Exit: true}}}
	p, _ := New(cfg)
	p.record(p.ups[1], "api.example.org", "443", true, 25*time.Millisecond)
	if err := p.SaveHistory(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(file)
	if bytes.Contains(raw, []byte("api.example.org")) {
		t.Fatal("history disclosed a destination name")
	}
	p, _ = New(cfg)
	if p.order("api.example.org", "443")[0].Name != "ByeDPI split" {
		t.Fatal("restart forgot the successful method")
	}
	if p.HasVerifiedExit() || p.aiPinned != "" {
		t.Fatal("saved history authorized an unverified exit")
	}
	if p.rememberedName("api.example.org", "8443") != "" {
		t.Fatal("port histories were merged")
	}
	cfg.HistoryKey = "mobile/fast"
	p, _ = New(cfg)
	if p.rememberedName("api.example.org", "443") != "" {
		t.Fatal("another network inherited the winner")
	}
	if err := os.WriteFile(file, []byte("damaged history"), 0600); err != nil {
		t.Fatal(err)
	}
	p, _ = New(cfg)
	p.record(p.ups[0], "example.org", "443", true, time.Millisecond)
	if err := p.SaveHistory(); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(file)
	if string(raw) != "damaged history" {
		t.Fatal("overwrote a damaged cache")
	}
}

func TestDemandExitJoinsTheOriginalClientHelloAndBecomesRemembered(t *testing.T) {
	var hits, calls atomic.Int32
	address := fakeSocks(t, destination(t), true, &hits)
	var p *Proxy
	p, _ = New(Config{Upstreams: []Upstream{{Name: "blocked local", Takeover: func(context.Context, string, string, []byte) (Session, error) { return nil, errors.New("blocked") }}},
		EnsureExit: func(ctx context.Context) error {
			calls.Add(1)
			return p.Add(Upstream{Name: "verified exit", Addr: address, Exit: true, AIEligible: true, Late: true})
		}})
	for range 2 {
		ctx, stop := context.WithTimeout(context.Background(), time.Second)
		w, err := p.race(ctx, "blocked.example", "443", clientHello())
		stop()
		if err != nil {
			t.Fatal(err)
		}
		w.release()
		if w.path != "verified exit" {
			t.Fatalf("wrong path: %s", w.path)
		}
	}
	if calls.Load() != 1 || hits.Load() != 2 {
		t.Fatalf("discovery repeated or original flight lost: calls=%d hits=%d", calls.Load(), hits.Load())
	}
}

func TestSpeculativeWindowIsBoundedAndStillTriesRemainingMethods(t *testing.T) {
	var active, maximum atomic.Int32
	entered := make(chan struct{}, 20)
	release := make(chan struct{})
	var ups []Upstream
	for i := range 20 {
		ups = append(ups, Upstream{Name: fmt.Sprint(i), Rank: i, Takeover: func(ctx context.Context, _, _ string, _ []byte) (Session, error) {
			current := active.Add(1)
			defer active.Add(-1)
			for previous := maximum.Load(); current > previous; previous = maximum.Load() {
				if maximum.CompareAndSwap(previous, current) {
					break
				}
			}
			entered <- struct{}{}
			if i == 19 {
				return rejectedSession{}, nil
			}
			select {
			case <-release:
				return nil, errors.New("blocked")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}})
	}
	p, _ := New(Config{Upstreams: ups, MaxParallel: 6, Stagger: time.Millisecond})
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	done := make(chan error, 1)
	go func() { w, err := p.race(ctx, "bounded.example", "443", clientHello()); w.release(); done <- err }()
	for range 6 {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("window never filled")
		}
	}
	select {
	case <-entered:
		t.Fatal("more than six speculative attempts")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if maximum.Load() > 6 {
		t.Fatalf("unbounded fanout: %d", maximum.Load())
	}
}

func TestMixedModeRecoversAPinnedExitOnlyAfterRemoval(t *testing.T) {
	p, _ := New(Config{ExitOnly: func(string) bool { return true }, RecoverPinnedExit: true, Upstreams: []Upstream{{Name: "a", Exit: true, AIEligible: true}, {Name: "b", Exit: true, AIEligible: true}}})
	p.record(p.ups[0], "protected.example", "443", true, time.Millisecond)
	if len(p.order("protected.example", "443")) != 1 {
		t.Fatal("healthy protected exit rotated")
	}
	p.Remove("a")
	order := p.order("protected.example", "443")
	if len(order) != 1 || order[0].Name != "b" {
		t.Fatal("dead pin blocked recovery")
	}
}

func TestHealthyLocalConnectionNeverRequestsATunnel(t *testing.T) {
	var hits, calls atomic.Int32
	p, _ := New(Config{Upstreams: []Upstream{{Name: "working local", Addr: fakeSocks(t, destination(t), true, &hits)}}, EnsureExit: func(context.Context) error { calls.Add(1); return errors.New("unexpected discovery") }})
	w, err := p.race(context.Background(), "local.example", "443", clientHello())
	if err != nil {
		t.Fatal(err)
	}
	w.release()
	if calls.Load() != 0 {
		t.Fatal("healthy local traffic launched a core")
	}
}

func TestProtectedDiscoveryFailureReachesConnectionDiagnostics(t *testing.T) {
	events := make(chan Event, 1)
	p, _ := New(Config{ExitOnly: func(string) bool { return true }, EnsureExit: func(context.Context) error { return context.DeadlineExceeded }, OnEvent: func(e Event) { events <- e }})
	if _, err := p.race(context.Background(), "protected.example", "443", clientHello()); err == nil {
		t.Fatal("unavailable exit reported success")
	}
	select {
	case e := <-events:
		if e.OK || e.Err == "" || e.Host != "protected.example" {
			t.Fatalf("failed discovery misreported: %+v", e)
		}
	default:
		t.Fatal("exit timeout was invisible to the UI")
	}
}

func TestCancelInterruptsAStalledSOCKSHandshake(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	p, _ := New(Config{Upstreams: []Upstream{{Name: "silent SOCKS", Addr: l.Addr().String()}}, ConnectTimeout: 10 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, err := p.dial(ctx, p.ups[0], "example.org", "443")
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(time.Second):
		t.Fatal("SOCKS dial never started")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled handshake succeeded")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("losing SOCKS attempt ignored cancellation")
	}
}
