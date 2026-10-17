package smartproxy

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
)

func TestBogusCoversBlockPageAndReservedRanges(t *testing.T) {
	for _, s := range []string{"10.10.34.35", "192.168.1.1", "127.0.0.1", "0.0.0.0", "169.254.1.1", "100.64.0.1", "224.0.0.1", "240.0.0.1", "fe80::1", "::1"} {
		if !Bogus(net.ParseIP(s)) {
			t.Errorf("%s must be treated as bogus", s)
		}
	}
	for _, s := range []string{"142.250.185.78", "104.16.248.249", "2a00:1450:4001:81b::200e"} {
		if Bogus(net.ParseIP(s)) {
			t.Errorf("%s is a normal public address", s)
		}
	}
}

func systemWith(answers map[string][]string) func(context.Context, string, string) ([]net.IP, error) {
	return func(_ context.Context, _ string, host string) ([]net.IP, error) {
		var out []net.IP
		for _, s := range answers[host] {
			out = append(out, net.ParseIP(s))
		}
		if len(out) == 0 {
			return nil, errors.New("no such host")
		}
		return out, nil
	}
}

func TestTrustedUsesCleanSystemAnswerWithoutEncryptedDNS(t *testing.T) {
	var dohCalls atomic.Int32
	doh := func(context.Context, string) ([]string, error) { dohCalls.Add(1); return nil, errors.New("unused") }
	r := NewTrusted(TrustedOptions{System: systemWith(map[string][]string{"example.org": {"93.184.216.34"}}), DoH: doh})
	ips, err := r(context.Background(), "example.org")
	if err != nil || len(ips) != 1 || ips[0] != "93.184.216.34" || dohCalls.Load() != 0 {
		t.Fatalf("ips=%v err=%v doh=%d", ips, err, dohCalls.Load())
	}
}

func TestTrustedDiscardsPoisonedAnswerAndAsksEncryptedDNS(t *testing.T) {
	sys := systemWith(map[string][]string{"www.example.org": {"10.10.34.35"}})
	// 198.18.0.0/15 is benchmarking space, not covered by Bogus: it stands in for a real answer.
	doh := func(context.Context, string) ([]string, error) { return []string{"198.18.0.5"}, nil }
	r := NewTrusted(TrustedOptions{System: sys, DoH: doh})
	ips, err := r(context.Background(), "www.example.org")
	if err != nil || len(ips) != 1 || ips[0] != "198.18.0.5" {
		t.Fatalf("ips=%v err=%v", ips, err)
	}
}

func TestTrustedFallsBackToGoogleFrontEndForGoogleNames(t *testing.T) {
	sys := systemWith(map[string][]string{
		"www.youtube.com": {"10.10.34.36"},
		"www.google.com":  {"142.250.185.100"},
	})
	broken := func(context.Context, string) ([]string, error) { return nil, errors.New("filtered") }
	r := NewTrusted(TrustedOptions{System: sys, DoH: broken})
	ips, err := r(context.Background(), "www.youtube.com")
	if err != nil || len(ips) != 1 || ips[0] != "142.250.185.100" {
		t.Fatalf("ips=%v err=%v", ips, err)
	}
	// A non-Google poisoned name must not get a Google address.
	sys2 := systemWith(map[string][]string{"blocked.example": {"10.10.34.37"}, "www.google.com": {"142.250.185.100"}})
	r2 := NewTrusted(TrustedOptions{System: sys2, DoH: broken})
	if _, err := r2(context.Background(), "blocked.example"); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("expected ErrPoisoned, got %v", err)
	}
}

func TestTrustedSkipsFilteredEncryptedDNSAfterRepeatedFailures(t *testing.T) {
	var calls atomic.Int32
	doh := func(context.Context, string) ([]string, error) { calls.Add(1); return nil, errors.New("filtered") }
	sys := systemWith(map[string][]string{})
	r := NewTrusted(TrustedOptions{System: sys, DoH: doh})
	for _, h := range []string{"a.example", "b.example", "c.example", "d.example", "e.example", "f.example"} {
		_, _ = r(context.Background(), h)
	}
	if calls.Load() != 3 {
		t.Fatalf("encrypted DNS asked %d times; must stop after 3 consecutive failures", calls.Load())
	}
}

func TestTrustedReopensEncryptedDNSWhenANewTransportAppears(t *testing.T) {
	var calls atomic.Int32
	var generation atomic.Uint64
	doh := func(context.Context, string) ([]string, error) { calls.Add(1); return nil, errors.New("filtered") }
	r := NewTrusted(TrustedOptions{System: systemWith(map[string][]string{}), DoH: doh, DoHGeneration: generation.Load})
	for _, h := range []string{"a.example", "b.example", "c.example", "d.example", "e.example"} {
		_, _ = r(context.Background(), h)
	}
	if calls.Load() != 3 {
		t.Fatalf("circuit did not open: %d calls", calls.Load())
	}
	generation.Store(1) // a tunnel came up
	_, _ = r(context.Background(), "f.example")
	if calls.Load() != 4 {
		t.Fatalf("new transport did not reopen encrypted DNS: %d calls", calls.Load())
	}
}

func TestExitCarriersTrackOnlyDNSCapableExits(t *testing.T) {
	p, err := New(Config{Upstreams: []Upstream{{Name: "plain", Addr: "127.0.0.1:1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if addrs, g := p.ExitCarriers(); len(addrs) != 0 || g != 0 {
		t.Fatalf("plain upstream counted as exit: %v %d", addrs, g)
	}
	if err := p.Add(Upstream{Name: "warp", Addr: "127.0.0.1:2", Exit: true}); err != nil {
		t.Fatal(err)
	}
	addrs, g := p.ExitCarriers()
	if len(addrs) != 1 || addrs[0] != "127.0.0.1:2" || g == 0 {
		t.Fatalf("exit not reported: %v %d", addrs, g)
	}
	p.Remove("warp")
	if addrs, g2 := p.ExitCarriers(); len(addrs) != 0 || g2 == g {
		t.Fatalf("removal did not change the inventory: %v %d", addrs, g2)
	}
}
