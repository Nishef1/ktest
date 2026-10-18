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

func TestStreamingCandidatesExhaustOnlyTheirRealInventory(t *testing.T) {
	for _, budget := range []int{0, 1000} {
		preset, next, err := ScanCandidateSource(context.Background(), "akamai", budget)
		if err != nil {
			t.Fatal(err)
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
			if seen[ip] {
				t.Fatalf("candidate repeated: %s", ip)
			}
			seen[ip] = true
		}
		if len(seen) != 8 || len(preset.IPs) != 8 {
			t.Fatalf("invented or lost Akamai inventory: %v", seen)
		}
	}
}

func TestCloudflareStreamIsLazyUniqueCancelableAndFinite(t *testing.T) {
	// A tiny official-range fixture makes genuine inventory exhaustion testable.
	old := cloudflareIPv4
	cloudflareIPv4 = []string{"103.21.244.0/30", "103.22.200.0/30"}
	t.Cleanup(func() { cloudflareIPv4 = old })
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
