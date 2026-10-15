package edges

import (
	"context"
	"testing"

	"github.com/Nishef1/ktest/internal/probe"
)

func TestRankValidTLSAndProofAbovePingOnly(t *testing.T) {
	plan := Plan{URL: "https://example.test/__ktest/proof", IPs: []string{"192.0.2.11", "192.0.2.12"}, Proof: true, Rounds: 2}
	run := func(_ context.Context, p probe.Config) (probe.Result, error) {
		if p.ConnectAddr == "192.0.2.11:443" {
			return probe.Result{Phase: "complete", TLSVersion: "TLS 1.3", Status: 200,
				Reachable: true, Success: true, ProofStatus: "verified", ElapsedMS: 25}, nil
		}
		return probe.Result{Phase: "complete", TLSVersion: "TLS 1.3", Status: 421,
			Reachable: true, ElapsedMS: 4}, nil
	}
	r, err := Run(context.Background(), plan, run)
	if err != nil || r.Candidates[0].IP != "192.0.2.11" || r.Candidates[0].Assessment != "origin_verified" ||
		r.Candidates[1].Assessment != "tls_only" {
		t.Fatalf("report=%+v err=%v", r, err)
	}
}

func TestUnverifiedHTTPNeverBecomesVerifiedOrigin(t *testing.T) {
	plan := Plan{URL: "https://example.test", IPs: []string{"2001:db8::1"}, Rounds: 1}
	run := func(_ context.Context, cfg probe.Config) (probe.Result, error) {
		if cfg.ConnectAddr != "[2001:db8::1]:443" {
			t.Fatalf("IPv6 address not bracketed: %s", cfg.ConnectAddr)
		}
		return probe.Result{TLSVersion: "TLS 1.3", Reachable: true, Status: 200, Success: true}, nil
	}
	r, err := Run(context.Background(), plan, run)
	if err != nil || r.Candidates[0].Assessment != "http_2xx_unverified" || r.Candidates[0].OriginVerified != 0 {
		t.Fatalf("report=%+v err=%v", r, err)
	}
}

func TestOnlyExplicitSingleIPsAndBoundedRuns(t *testing.T) {
	bad := []Plan{
		{URL: "http://example.test", IPs: []string{"192.0.2.1"}, Rounds: 1},
		{URL: "https://example.test", IPs: []string{"192.0.2.0/24"}, Rounds: 1},
		{URL: "https://example.test", IPs: []string{"192.0.2.1"}, Rounds: 12},
	}
	for _, p := range bad {
		if _, err := Run(context.Background(), p, nil); err == nil {
			t.Fatalf("invalid plan passed: %+v", p)
		}
	}
}
