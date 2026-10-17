package main

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/Nishef1/ktest/internal/quickcheck"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

const routeRefreshInterval = 15 * time.Minute

func trackUserEvent(activity *atomic.Uint64, e smartproxy.Event) bool {
	if e.Probe {
		return false
	}
	if !e.Rejected && !e.EarlyClose {
		activity.Add(1)
	}
	return true
}

// Reuse normal destination racing and its failure feedback. Refreshes do not
// reset history, replay application requests, or elect one global winner.
func startRouteRefresh(ctx context.Context, port int, activity *atomic.Uint64, t *term) func() {
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	seen := activity.Load()
	go func() {
		defer close(done)
		tick := time.NewTicker(routeRefreshInterval)
		defer tick.Stop()
		runRouteRefresh(rctx, tick.C, activity, seen, func(ctx context.Context) {
			results := quickcheck.Run(ctx, port, 8*time.Second)
			if ctx.Err() != nil {
				return
			}
			passed := proxiedPassCount(results)
			k := toneInfo
			if passed == 0 {
				k = toneWarn
			}
			t.Line(k, "Route refresh: %d of %d small site probes verified; per-destination history updated", passed, len(results))
		})
	}()
	return func() { cancel(); <-done }
}

func runRouteRefresh(ctx context.Context, ticks <-chan time.Time, activity *atomic.Uint64, seen uint64, refresh func(context.Context)) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ticks:
			if !ok {
				return
			}
			current := activity.Load()
			if current == seen {
				continue
			}
			refresh(ctx)
			// Internal events are tagged separately; keep real user activity
			// arriving during this refresh eligible for the next interval.
			seen = current
		}
	}
}

func waitForVerifiedExit(ctx context.Context, p *smartproxy.Proxy) bool {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for !p.HasVerifiedExit() {
		select {
		case <-ctx.Done():
			return false
		case <-tick.C:
		}
	}
	return ctx.Err() == nil
}
