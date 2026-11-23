package smartproxy

import (
	"context"
	"testing"
	"time"
)

func TestLiveRecheckChallengesStableWinnerWithoutBackgroundRequests(t *testing.T) {
	p, err := New(Config{Upstreams: []Upstream{{Name: "original"}, {Name: "alternative", Rank: 1}}, RecheckInterval: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	host, port := "stable.example.org", "443"
	for i := 0; i < 3; i++ {
		p.record(p.ups[0], host, port, true, 10*time.Millisecond)
	}
	if got := p.maybeRecheckRoute(host, port, p.order(host, port)); got[0].Name != "original" {
		t.Fatalf("cold startup lost saved preference: %s", got[0].Name)
	}
	p.started = time.Now().Add(-11 * time.Minute)
	if got := p.maybeRecheckRoute(host, port, p.order(host, port)); got[0].Name != "alternative" {
		t.Fatalf("first opportunity did not test a different route: %s", got[0].Name)
	}
	if got := p.maybeRecheckRoute(host, port, p.order(host, port)); got[0].Name != "original" {
		t.Fatalf("recheck ran again without the interval: %s", got[0].Name)
	}
	if winner := p.rememberedName(host, port); winner != "original" {
		t.Fatalf("exploration changed the winner without evidence: %s", winner)
	}
}

func TestLiveRecheckRespectsNetworkPoliciesAndUnhealthyRoutes(t *testing.T) {
	variants := []struct {
		name   string
		config Config
	}{
		{"protected", Config{ExitOnly: func(string) bool { return true }, Upstreams: []Upstream{{Name: "exit-a", Exit: true, AIEligible: true}, {Name: "exit-b", Exit: true, AIEligible: true}}}},
		{"carrier", Config{ExitRequired: func(string) bool { return true }, Upstreams: []Upstream{{Name: "exit-a", Exit: true}, {Name: "exit-b", Exit: true}}}},
		{"frozen", Config{Frozen: &FrozenRoutes{Default: "a"}, Upstreams: []Upstream{{Name: "a"}, {Name: "b"}}}},
		{"local-only", Config{LocalOnly: true, Upstreams: []Upstream{{Name: "a", LocalBypass: true, Addr: "127.0.0.1:10001"}, {Name: "b", LocalBypass: true, Addr: "127.0.0.1:10002"}}}},
	}
	for _, item := range variants {
		t.Run(item.name, func(t *testing.T) {
			p, err := New(item.config)
			if err != nil {
				t.Fatal(err)
			}
			p.started = time.Now().Add(-11 * time.Minute)
			for i := 0; i < 3; i++ {
				p.record(p.ups[0], "protected.example", "443", true, time.Millisecond)
			}
			ordered := p.order("protected.example", "443")
			if len(ordered) == 0 {
				t.Fatal("no routes")
			}
			chosen := p.maybeRecheckRoute("protected.example", "443", ordered)
			if chosen[0].Name != ordered[0].Name {
				t.Fatalf("protected policy challenged %s", ordered[0].Name)
			}
		})
	}
}

func TestLiveRecheckSkipsCoolingAndDifferentEgressClass(t *testing.T) {
	p, err := New(Config{Upstreams: []Upstream{{Name: "local"}, {Name: "exit", Exit: true, AIEligible: true}, {Name: "front", Takeover: func(context.Context, string, string, []byte) (Session, error) { return nil, nil }}}})
	if err != nil {
		t.Fatal(err)
	}
	p.started = time.Now().Add(-11 * time.Minute)
	for i := 0; i < 3; i++ {
		p.record(p.ups[0], "site.example", "443", true, time.Millisecond)
	}
	if result := p.maybeRecheckRoute("site.example", "443", p.order("site.example", "443")); result[0].Name != "local" {
		t.Fatalf("recheck crossed route class: %s", result[0].Name)
	}
	p2, _ := New(Config{Upstreams: []Upstream{{Name: "local"}, {Name: "other", Rank: 1}}})
	p2.started = time.Now().Add(-11 * time.Minute)
	for i := 0; i < 3; i++ {
		p2.record(p2.ups[0], "site.example", "443", true, time.Millisecond)
	}
	p2.record(p2.ups[1], "site.example", "443", false, time.Second)
	p2.record(p2.ups[1], "site.example", "443", false, time.Second)
	if got := p2.maybeRecheckRoute("site.example", "443", p2.order("site.example", "443")); got[0].Name != "local" {
		t.Fatalf("cooldown skipped: %s", got[0].Name)
	}
}
