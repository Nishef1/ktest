package mobilebridge

import (
	"context"
	"net"
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

func TestAutomaticDiscoveryStartsIndependentBackendsWhileWarpStalls(t *testing.T) {
	a := newAutomaticExit("balanced", "", t.TempDir(), "test-network")
	defer a.stop()
	warpStarted, psiphonStarted := make(chan struct{}), make(chan struct{})
	a.attempt = func(ctx context.Context, p aether.Profile) (*nativeCore, observedExit, error) {
		switch p.Label {
		case "warp":
			close(warpStarted)
		case "psiphon":
			close(psiphonStarted)
		case "tor":
			select {
			case <-warpStarted:
			case <-ctx.Done():
				return nil, observedExit{}, ctx.Err()
			}
			select {
			case <-psiphonStarted:
			case <-ctx.Done():
				return nil, observedExit{}, ctx.Err()
			}
			n := &nativeCore{address: "127.0.0.1:12345", done: make(chan struct{})}
			var once sync.Once
			n.cancel = func() { once.Do(func() { close(n.done) }) }
			return n, observedExit{Address: n.address, Region: "DE"}, nil
		}
		<-ctx.Done()
		return nil, observedExit{}, ctx.Err()
	}
	profiles := []aether.Profile{
		{Label: "warp", Args: []string{"--masque", "--h2"}},
		{Label: "warp-variant", Args: []string{"--masque", "--h3"}},
		{Label: "warp-variant-2", Args: []string{"--wg"}},
		{Label: "psiphon", Args: []string{"--psiphon-only", "--psiphon-mode", "cdn"}},
		{Label: "tor", Args: []string{"--tor-only"}},
	}
	finished := make(chan *nativeResult, 1)
	go func() { finished <- a.discover(profiles) }()
	select {
	case r := <-finished:
		if r == nil || r.profile.Label != "tor" {
			t.Fatal("independent Tor backend was not selected")
		}
		r.core.stop()
	case <-time.After(time.Second):
		a.cancel()
		<-finished
		t.Fatal("blocked WARP variants prevented the independent backends from starting")
	}
}

func TestAutomaticStandaloneExitsUseAnIndependentLocalCarrier(t *testing.T) {
	a := newAutomaticExit("balanced", "", t.TempDir(), "test-network")
	defer func() {
		if a.carrier != nil {
			a.carrier.Stop()
		}
		a.stop()
	}()
	profiles := aether.WithLocalCarriers([]aether.Profile{
		{Label: "Psiphon", Args: []string{"--psiphon-only"}},
		{Label: "Tor", Args: []string{"--tor-only"}},
	})
	if len(profiles) != 4 {
		t.Fatal("missing direct/carried independent backends")
	}
	for _, p := range profiles {
		o, err := a.optionsForProfile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !p.LocalCarrier() {
			if o.carrier != "" {
				t.Fatal("direct native transports were replaced with TCP-only SOCKS")
			}
			continue
		}
		host, _, err := net.SplitHostPort(o.carrier)
		if err != nil || host != "127.0.0.1" {
			t.Fatalf("%s did not receive an owned carrier: %+v", p.Label, o)
		}
		c, err := net.DialTimeout("tcp", o.carrier, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		if o.profile.ID() != p.ID() {
			t.Fatal("carrier setup changed the exit profile")
		}
	}
}
