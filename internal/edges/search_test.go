package edges

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

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
		for _, raw := range prefixesFor("cloudflare") {
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
	if ips, err := CloudflareCandidates(1000); err != nil || len(ips) != 1000 {
		t.Fatalf("larger finite budget rejected: count=%d err=%v", len(ips), err)
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
	if err != nil || !out.ReachedGoal || len(out.VerifiedHTTP) < 10 || out.Attempted > len(ips) {
		t.Fatalf("result=%+v err=%v", out, err)
	}
}

func TestScanZeroGoalHonorsLargeBudget(t *testing.T) {
	ips, err := CloudflareCandidates(517)
	if err != nil {
		t.Fatal(err)
	}
	var reported int
	out, err := ScanCDN(context.Background(), ips, "https://www.cloudflare.com/", 0,
		func(ctx context.Context, cfg probe.Config) (probe.Result, error) {
			if cfg.Timeout != 4*time.Second || cfg.MaxBodyBytes > 512 || cfg.Host != "" || cfg.ServerName != "" || cfg.Proof {
				t.Errorf("unexpected probe policy: %+v", cfg)
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Error("request context lacks timeout")
			}
			return probe.Result{Success: true, TLSVersion: "TLS 1.3", Status: 200}, nil
		}, func(_ string, _ probe.Result, attempted, verified int) {
			reported++
			if attempted != reported || verified != reported {
				t.Errorf("counts attempted=%d verified=%d reported=%d", attempted, verified, reported)
			}
		})
	if err != nil || out.Attempted != 517 || reported != 517 || out.TotalVerified != 517 || out.ReachedGoal || !out.Exhausted {
		t.Fatalf("scan=%+v reports=%d err=%v", out, reported, err)
	}
	if len(out.VerifiedHTTP) > 100 {
		t.Fatalf("unbounded retained successes: %d", len(out.VerifiedHTTP))
	}
}

func TestScanCancellationDrainsAllSixInflightAttempts(t *testing.T) {
	ips, _ := CloudflareCandidates(50)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var active, calls atomic.Int32
	ready := make(chan struct{}, 6)
	done := make(chan ScanOutcome, 1)
	errCh := make(chan error, 1)
	go func() {
		out, err := ScanCDN(ctx, ips, "https://www.cloudflare.com/", 0,
			func(ctx context.Context, _ probe.Config) (probe.Result, error) {
				calls.Add(1)
				if active.Add(1) > 6 {
					t.Error("more than six concurrent requests")
				}
				defer active.Add(-1)
				ready <- struct{}{}
				<-ctx.Done()
				return probe.Result{Error: "context canceled"}, nil
			}, nil)
		done <- out
		errCh <- err
	}()
	for range 6 {
		select {
		case <-ready:
		case <-time.After(time.Second):
			t.Fatal("six workers did not start")
		}
	}
	cancel()
	select {
	case out := <-done:
		if out.Attempted != 6 || calls.Load() != 6 || active.Load() != 0 || out.Exhausted || !errors.Is(<-errCh, context.Canceled) {
			t.Fatalf("cancellation lost attempts: %+v calls=%d active=%d", out, calls.Load(), active.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not join workers")
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
