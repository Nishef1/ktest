package smartproxy

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestFrozenRouteDoesNotRaceOrFallbackAfterFailure(t *testing.T) {
	var selected, alternate atomic.Int32
	p, err := New(Config{
		Upstreams: []Upstream{
			{Name: "selected", Addr: silentSocks(t, &selected)},
			{Name: "alternate", Addr: fakeSocks(t, destination(t), true, &alternate)},
		},
		Frozen:  &FrozenRoutes{Default: "selected"},
		Stagger: time.Millisecond, FirstByteTimeout: 40 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Even a remembered faster alternative must not change the session choice.
	p.record(p.ups[1], "api.example.org", "443", true, time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	w, err := p.race(ctx, "api.example.org", "443", clientHello())
	w.release()
	if err == nil || selected.Load() != 1 || alternate.Load() != 0 {
		t.Fatalf("session switched routes: err=%v selected=%d alternate=%d", err, selected.Load(), alternate.Load())
	}
	p.Remove("selected")
	w, err = p.race(ctx, "api.example.org", "443", clientHello())
	w.release()
	if err == nil || alternate.Load() != 0 {
		t.Fatal("removing a dead selected method enabled automatic fallback")
	}
}

func TestFrozenDestinationsAndPolicyRemainIsolated(t *testing.T) {
	pins := &FrozenRoutes{Default: "local", Protected: "exit", Targets: map[string]string{"api.example.org:443": "specific", "blocked.example.org:443": ""}}
	p, err := New(Config{Frozen: pins, ExitOnly: func(h string) bool { return h == "protected.example" }, Upstreams: []Upstream{
		{Name: "local"}, {Name: "specific"}, {Name: "exit", Exit: true, AIEligible: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	pins.Targets["api.example.org:443"] = "local"
	pins.Default = "exit"
	for _, tc := range []struct{ host, want string }{
		{"api.example.org", "specific"}, {"other.example", "local"}, {"protected.example", "exit"},
	} {
		order := p.order(tc.host, "443")
		if len(order) != 1 || order[0].Name != tc.want {
			t.Fatalf("%s did not retain its immutable selected route", tc.host)
		}
	}
	if len(p.order("blocked.example.org", "443")) != 0 {
		t.Fatal("a failed tested destination silently used the default route")
	}
	p.Remove("exit")
	if len(p.order("protected.example", "443")) != 0 {
		t.Fatal("a protected destination escaped its missing verified exit")
	}
}

func TestFrozenSessionReverifiesSameExitAfterLeaseExpires(t *testing.T) {
	var checks atomic.Int32
	p, err := New(Config{Frozen: &FrozenRoutes{Protected: "exit"}, Upstreams: []Upstream{{Name: "exit", Exit: true, AIEligible: true}},
		VerifyExit: func(context.Context, Upstream) error { checks.Add(1); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	p.ups[0].verifiedUntil.Store(time.Now().Add(-time.Second).UnixNano())
	if err := p.verifyExit(context.Background(), p.ups[0]); err != nil || checks.Load() != 1 {
		t.Fatalf("fixed foreign exit did not refresh verification: err=%v checks=%d", err, checks.Load())
	}
	if err := p.verifyExit(context.Background(), p.ups[0]); err != nil || checks.Load() != 1 {
		t.Fatalf("fresh verification was not cached: err=%v checks=%d", err, checks.Load())
	}
	if got := p.order("protected.example", "443"); len(got) != 1 || got[0].Name != "exit" {
		t.Fatalf("verification refresh changed the frozen route: %+v", got)
	}
}

func TestFrozenSessionRejectsFailedExitReverification(t *testing.T) {
	var checks atomic.Int32
	p, err := New(Config{Frozen: &FrozenRoutes{Protected: "exit"}, Upstreams: []Upstream{{Name: "exit", Exit: true, AIEligible: true}},
		VerifyExit: func(context.Context, Upstream) error {
			checks.Add(1)
			return errors.New("foreign exit is unavailable")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	p.ups[0].verifiedUntil.Store(time.Now().Add(-time.Second).UnixNano())
	if err := p.verifyExit(context.Background(), p.ups[0]); err == nil || checks.Load() != 1 {
		t.Fatalf("unverified foreign exit was accepted: err=%v checks=%d", err, checks.Load())
	}
}

func TestUntestedChildrenUseDefaultNotParentFrontingSelection(t *testing.T) {
	for _, parentMethod := range []string{"front-only", ""} {
		p, err := New(Config{Frozen: &FrozenRoutes{Default: "generic", Targets: map[string]string{"x.com:443": parentMethod}},
			Upstreams: []Upstream{{Name: "generic"}, {Name: "front-only", Match: func(host string) bool { return host == "x.com" }}},
		})
		if err != nil {
			t.Fatal(err)
		}
		order := p.order("unknown.x.com", "443")
		if len(order) != 1 || order[0].Name != "generic" {
			t.Fatalf("untested child inherited parent selection %q instead of its default", parentMethod)
		}
	}
}
