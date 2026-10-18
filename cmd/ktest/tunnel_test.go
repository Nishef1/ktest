package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestTunnelReadinessDoesNotImposeAnUnconditionalStartupWait(t *testing.T) {
	began := time.Now()
	if err := waitTunnelReady(context.Background(), make(chan struct{}), func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	if time.Since(began) > time.Second {
		t.Fatal("ready adapter incurred a fixed startup wait")
	}
}

func TestTunnelReadinessRejectsExitAndCancellation(t *testing.T) {
	done := make(chan struct{})
	close(done)
	if err := waitTunnelReady(context.Background(), done, func() bool { return true }); err == nil {
		t.Fatal("exited tunnel considered ready")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitTunnelReady(ctx, make(chan struct{}), func() bool { return true }); err != context.Canceled {
		t.Fatal(err)
	}
}

func TestSystemRouteProofRequiresTheTunnelSource(t *testing.T) {
	for _, c := range []struct {
		output string
		ok     bool
	}{
		{"204|172.19.0.1", true}, {"200|fdfe:dcba:9876::1", true},
		{"204|192.168.1.2", false}, {"204|", false}, {"500|172.19.0.1", false},
	} {
		if got := parseSystemRouteResult("https://example.com", c.output, nil); got.ok != c.ok {
			t.Fatalf("%q: %+v", c.output, got)
		}
	}
}

func TestTunnelRestoresResolverOnceEvenAfterNativeExitAndManualStop(t *testing.T) {
	var calls atomic.Int32
	tn := &tunnel{restore: func() { calls.Add(1) }}
	tn.restoreDNS()
	tn.restoreDNS()
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver cleanup executed %d times", got)
	}
}
