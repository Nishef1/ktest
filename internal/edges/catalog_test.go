package edges

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestAkamaiPresetIsSmallAndSourceAttributed(t *testing.T) {
	p, err := PresetCandidates(context.Background(), "akamai")
	if err != nil {
		t.Fatal(err)
	}
	if p.Provider != "akamai" || len(p.IPs) == 0 || len(p.IPs) > 12 || p.Source == "" || p.URL == "" {
		t.Fatalf("invalid source-backed preset: %+v", p)
	}
	for _, ip := range p.IPs {
		if ip == "127.0.0.1" {
			t.Fatal("local addresses must not be seeds")
		}
	}
}

func TestStreamingCandidatesSeedThenCoverTheWholeProviderInventory(t *testing.T) {
	prefixOverride = map[string][]string{"akamai": {"23.12.147.0/30", "2.16.0.0/30", "198.51.0.7/32"}}
	t.Cleanup(func() { prefixOverride = nil })
	for _, budget := range []int{0, 5} {
		preset, next, err := ScanCandidateSource(context.Background(), "akamai", budget)
		if err != nil {
			t.Fatal(err)
		}
		var order []string
		seen := map[string]bool{}
		for {
			ip, ok, err := next(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				break
			}
			if seen[ip] {
				t.Fatalf("candidate repeated: %s", ip)
			}
			seen[ip] = true
			order = append(order, ip)
		}
		// Eight seeds, then two hosts per /30 and the single published edge.
		want := 8 + 2 + 2 + 1
		if budget > 0 {
			want = budget
		}
		if len(order) != want || order[0] != "92.123.102.43" || preset.InventorySize != 13 {
			t.Fatalf("budget %d: %d candidates %v inventory %d", budget, len(order), order, preset.InventorySize)
		}
	}
}

func TestEveryProviderHasAnInventory(t *testing.T) {
	for _, p := range []string{"cloudflare", "akamai", "fastly", "google", "meta", "cloudfront", "gcore"} {
		if inventorySize(prefixesFor(p)) < 500 {
			t.Errorf("%s: inventory %d", p, inventorySize(prefixesFor(p)))
		}
	}
}

func TestCloudflareStreamIsLazyUniqueCancelableAndFinite(t *testing.T) {
	// A tiny official-range fixture makes genuine inventory exhaustion testable.
	prefixOverride = map[string][]string{"cloudflare": {"103.21.244.0/30", "103.22.200.0/30"}}
	t.Cleanup(func() { prefixOverride = nil })
	p, next, err := ScanCandidateSource(context.Background(), "cloudflare", 0)
	if err != nil || len(p.IPs) != 0 {
		t.Fatalf("source eagerly materialized inventory: %+v %v", p, err)
	}
	seen := map[string]bool{}
	for {
		ip, ok, err := next(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		addr := netip.MustParseAddr(ip)
		if seen[ip] || !(netip.MustParsePrefix("103.21.244.0/30").Contains(addr) || netip.MustParsePrefix("103.22.200.0/30").Contains(addr)) {
			t.Fatalf("duplicate or out-of-inventory IP %s", ip)
		}
		seen[ip] = true
	}
	if len(seen) != 4 {
		t.Fatalf("usable inventory size=%d, want four hosts", len(seen))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := next(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ignored: %v", err)
	}
}

func TestUnknownPresetRejectedWithoutNetwork(t *testing.T) {
	if _, err := PresetCandidates(context.Background(), "unknown"); err == nil {
		t.Fatal("unknown provider accepted")
	}
}
