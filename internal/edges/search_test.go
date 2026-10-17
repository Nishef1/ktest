package edges

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/Nishef1/ktest/internal/probe"
)

func TestCloudflareCandidatesUniqueAndProviderOwned(t *testing.T) {
	ips, err := CloudflareCandidates(300)
	if err != nil || len(ips) != 300 {
		t.Fatalf("candidates=%d err=%v", len(ips), err)
	}
	seen := map[string]bool{}
	for _, s := range ips {
		ip, err := netip.ParseAddr(s)
		if err != nil || seen[s] {
			t.Fatalf("invalid or duplicate IP: %q", s)
		}
		seen[s] = true
		owned := false
		for _, raw := range cloudflareIPv4 {
			p, _ := netip.ParsePrefix(raw)
			if p.Contains(ip) {
				owned = true
				break
			}
		}
		if !owned {
			t.Fatalf("IP outside official Cloudflare ranges: %s", s)
		}
	}
	if _, err := CloudflareCandidates(500); err == nil {
		t.Fatal("unbounded scan accepted")
	}
}

func TestScanStopsAt10ValidHTTPSAndRejectsTCPOnly(t *testing.T) {
	ips, _ := CloudflareCandidates(100)
	runner := func(ctx context.Context, p probe.Config) (probe.Result, error) {
		ip, _, _ := net.SplitHostPort(p.ConnectAddr)
		if ip == ips[0] {
			return probe.Result{Phase: "tls", Reachable: true}, nil
		}
		return probe.Result{Success: true, TLSVersion: "TLS 1.3", Status: 200}, nil
	}
	out, err := ScanCDN(context.Background(), ips, "https://www.cloudflare.com/cdn-cgi/trace", 10, runner, nil)
	if err != nil || !out.ReachedGoal || len(out.VerifiedHTTP) != 10 || out.Attempted > len(ips) {
		t.Fatalf("result=%+v err=%v", out, err)
	}
}

func TestScanStopsAfterBudgetWhenNothingWorks(t *testing.T) {
	ips, _ := CloudflareCandidates(23)
	runner := func(ctx context.Context, p probe.Config) (probe.Result, error) {
		return probe.Result{Phase: "tls", Reachable: true, Status: 421}, nil
	}
	out, err := ScanCDN(context.Background(), ips, "https://www.cloudflare.com/cdn-cgi/trace", 10, runner, nil)
	if err != nil || out.ReachedGoal || out.Attempted != 23 || len(out.VerifiedHTTP) != 0 {
		t.Fatalf("result=%+v err=%v", out, err)
	}
}

func TestScanUsesEachCandidatesActualIPFamily(t *testing.T) {
	families := make(chan string, 2)
	out, err := ScanCDN(context.Background(), []string{"192.0.2.1", "2001:db8::1"}, "https://example.com", 2,
		func(_ context.Context, cfg probe.Config) (probe.Result, error) {
			families <- cfg.Network
			return probe.Result{Success: true, TLSVersion: "TLS 1.3", Status: 200}, nil
		}, nil)
	if err != nil || !out.ReachedGoal {
		t.Fatalf("scan=%+v, %v", out, err)
	}
	got := map[string]int{}
	for range 2 {
		got[<-families]++
	}
	if got["tcp4"] != 1 || got["tcp6"] != 1 {
		t.Fatalf("wrong address-family selection: %v", got)
	}
}
