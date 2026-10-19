package main

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Nishef1/ktest/internal/aether"
	"github.com/Nishef1/ktest/internal/cdnranges"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

func TestCarrierSourceKeepsOnlyLocalRoutes(t *testing.T) {
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, nil }
	ups := append(smartproxy.PlainUpstreams(), smartproxy.DesyncUpstreams()...)
	ups = append(ups,
		smartproxy.Upstream{Name: "ByeDPI x", Addr: "127.0.0.1:10812", LocalBypass: true},
		smartproxy.Upstream{Name: "Zapret2 split", Dial: dial, LocalBypass: true},
		smartproxy.Upstream{Name: "Tor-only", Addr: "127.0.0.1:18991", Exit: true},
		smartproxy.Upstream{Name: "Xray profile", Addr: "127.0.0.1:10808"},
	)
	got := carrierSourceUpstreams(ups)
	var names []string
	for _, u := range got {
		names = append(names, u.Name)
	}
	for _, want := range []string{"ByeDPI x", "Zapret2 split"} {
		if !slices.Contains(names, want) {
			t.Errorf("carrier lost %q: %v", want, names)
		}
	}
	for _, bad := range []string{"Tor-only", "Xray profile"} {
		if slices.Contains(names, bad) {
			t.Errorf("carrier kept %q: %v", bad, names)
		}
	}
	if len(got) != len(ups)-2 {
		t.Fatalf("plain and desync routes must all be kept: %v", names)
	}
	if p, err := newCarrierSource(nil, smartproxy.Config{}); p != nil || err != nil {
		t.Fatalf("no routes must mean no carrier, got %v %v", p, err)
	}
}

func TestCarriedExitArgs(t *testing.T) {
	psiphon := aetherProfile{Label: "Psiphon", Args: []string{"--psiphon-only"}}
	tor := aetherProfile{Label: "Tor-only", Args: []string{"--tor-only"}}
	h2 := aetherProfile{Label: "MASQUE H2", Args: []string{"--masque", "--http2"}}
	pinned := aetherProfile{Label: "Psiphon pinned", Args: []string{"--psiphon-only", "--upstream", "socks5://127.0.0.1:9"}}
	if !carriesExit(psiphon) || !carriesExit(tor) || carriesExit(h2) || carriesExit(pinned) {
		t.Fatal("only standalone Psiphon/Tor without their own upstream are carried")
	}
	args, err := withCarrier([]string{"--tor-only", "--bind", "127.0.0.1:18991"}, "127.0.0.1:4321")
	if err != nil || strings.Join(args, " ") != "--tor-only --bind 127.0.0.1:18991 --upstream socks5://127.0.0.1:4321" {
		t.Fatalf("withCarrier = %v, %v", args, err)
	}
	if _, err := withCarrier([]string{"--tor-only"}, "203.0.113.1:1080"); err == nil {
		t.Fatal("a non-loopback carrier must be refused")
	}
	edges := []string{"23.0.0.1", "104.16.0.1"}
	if got := withPsiphonEdges([]string{"--psiphon-only"}, psiphon, edges); strings.Join(got, " ") != "--psiphon-only --psiphon-cdn-ips 23.0.0.1,104.16.0.1" {
		t.Fatalf("edges not passed: %v", got)
	}
	for _, p := range []aetherProfile{tor, {Args: []string{"--psiphon-only", "--psiphon-cdn-ips", "1.1.1.1"}}} {
		if got := withPsiphonEdges(p.Args, p, edges); !slices.Equal(got, p.Args) {
			t.Fatalf("%v must keep its args, got %v", p.Args, got)
		}
	}
}

func TestPsiphonCDNEdgesSpreadAcrossProviders(t *testing.T) {
	set := cdnranges.Current()
	edges := psiphonCDNEdges(set)
	if len(edges) == 0 || len(edges) > maxPsiphonEdges {
		t.Fatalf("got %d edges, want 1..%d", len(edges), maxPsiphonEdges)
	}
	seen := map[string]bool{}
	providers := map[string]int{}
	for _, ip := range edges {
		if _, err := netip.ParseAddr(ip); err != nil || seen[ip] {
			t.Fatalf("bad or duplicate edge %q", ip)
		}
		seen[ip] = true
		for _, p := range psiphonEdgeProviders {
			if set.Contains(p, ip) {
				providers[p]++
				break
			}
		}
	}
	for _, p := range psiphonEdgeProviders {
		if set.Size(p) > 0 && providers[p] == 0 {
			t.Errorf("no %s edges in %v", p, edges)
		}
	}
	if psiphonCDNEdges(nil) != nil {
		t.Fatal("nil inventory must give no edges")
	}
}

func TestCarriedTorArgsRunsThroughOwnedCarrier(t *testing.T) {
	source, err := smartproxy.New(smartproxy.Config{Upstreams: smartproxy.PlainUpstreams()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	args, carrier, err := carriedTorArgs(ctx, []string{"--tor-only"}, source)
	if err != nil {
		t.Fatal(err)
	}
	defer carrier.Stop()
	want := "socks5://" + carrier.SOCKS.Addr().String()
	if aetherProfile := (aether.Profile{Args: args}); aetherProfile.Value("--upstream") != want {
		t.Fatalf("args %v do not use carrier %s", args, want)
	}
}
