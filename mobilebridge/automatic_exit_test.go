package mobilebridge

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
)

func TestAutomaticDiscoveryKeepsTheWinnerAndReapsLosingCore(t *testing.T) {
	a := newAutomaticExit("balanced", "", t.TempDir(), "test-network")
	defer a.stop()
	var starts, stops atomic.Int32
	firstStarted := make(chan struct{})
	a.attempt = func(ctx context.Context, p aether.Profile) (*nativeCore, observedExit, error) {
		starts.Add(1)
		var once sync.Once
		n := &nativeCore{address: "127.0.0.1:12345", method: p.Method(), done: make(chan struct{})}
		n.cancel = func() { once.Do(func() { stops.Add(1); close(n.done) }) }
		if p.Label == "blocked" {
			close(firstStarted)
			<-ctx.Done()
			n.stop()
			return nil, observedExit{}, ctx.Err()
		}
		<-firstStarted
		return n, observedExit{Address: n.address, Region: "DE"}, nil
	}
	finished := make(chan *nativeResult, 1)
	go func() {
		finished <- a.discover([]aether.Profile{{Label: "blocked", Args: []string{"--masque"}}, {Label: "working", Args: []string{"--psiphon-only", "--psiphon-mode", "cdn"}}})
	}()
	select {
	case r := <-finished:
		if r == nil || r.profile.Label != "working" {
			t.Fatal("discovery lost the successful method")
		}
		select {
		case <-r.core.done:
			t.Fatal("request cleanup killed the selected core")
		default:
		}
		if starts.Load() != 2 || stops.Load() != 1 {
			t.Fatalf("loser not reaped: starts=%d stops=%d", starts.Load(), stops.Load())
		}
		r.core.stop()
	case <-time.After(time.Second):
		t.Fatal("a blocked method delayed a working independent transport")
	}
}

func TestMobileRouteHistorySeparatesNetworksAndModes(t *testing.T) {
	routeNetworkMu.Lock()
	previous := routeNetworkToken
	routeNetworkToken = ""
	routeNetworkMu.Unlock()
	defer func() { routeNetworkMu.Lock(); routeNetworkToken = previous; routeNetworkMu.Unlock() }()
	dir := t.TempDir()
	if file, _ := mobileHistory("fast", dir); file != "" {
		t.Fatal("history without a network identity was enabled")
	}
	_ = SetRouteNetworkToken("wifi:100")
	a, ka := mobileHistory("fast", dir)
	b, kb := mobileHistory("balanced", dir)
	_ = SetRouteNetworkToken("cellular:200")
	c, kc := mobileHistory("fast", dir)
	if a == "" || a == b || a == c || ka == kb || ka == kc {
		t.Fatal("mode/network histories collided")
	}
}
