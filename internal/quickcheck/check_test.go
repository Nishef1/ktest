package quickcheck

import (
	"context"
	"testing"
	"time"
)

func TestClosedProxyFailsRatherThanClaimingAccess(t *testing.T) {
	// A closed loopback SOCKS listener must never produce an apparent success.
	results := Run(context.Background(), 1, 500*time.Millisecond)
	if len(results) != 2 {
		t.Fatalf("got %d results", len(results))
	}
	for _, r := range results {
		if r.Success || r.Detail == "" {
			t.Fatalf("false positive: %+v", r)
		}
	}
}

func TestCancelledProbeProducesNoSuccess(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	stop()
	results := Run(ctx, 10808, time.Second)
	for _, r := range results {
		if r.Success {
			t.Fatalf("cancelled probe succeeded: %+v", r)
		}
	}
}
