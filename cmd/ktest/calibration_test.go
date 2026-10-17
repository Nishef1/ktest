package main

import (
	"context"
	"github.com/Nishef1/ktest/internal/smartproxy"
	"sync/atomic"
	"testing"
	"time"
)

func TestRouteRefreshSkipsIdleSessionsAndDoesNotFeedItself(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time)
	calls := make(chan struct{}, 4)
	done := make(chan struct{})
	var activity atomic.Uint64
	go func() {
		defer close(done)
		runRouteRefresh(ctx, ticks, &activity, 0, func(context.Context) {
			trackUserEvent(&activity, smartproxy.Event{Probe: true, OK: true})
			calls <- struct{}{}
		})
	}()
	quiet := func() {
		t.Helper()
		ticks <- time.Now()
		select {
		case <-calls:
			t.Fatal("idle session triggered probes")
		case <-time.After(30 * time.Millisecond):
		}
	}
	quiet()
	for i := 0; i < 2; i++ {
		activity.Add(1)
		ticks <- time.Now()
		select {
		case <-calls:
		case <-time.After(time.Second):
			t.Fatal("active session was not refreshed")
		}
		quiet()
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("refresh did not stop")
	}
}

func TestRefreshKeepsConcurrentUserActivityAndIgnoresLateProbeEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var activity atomic.Uint64
	activity.Store(1)
	ticks := make(chan time.Time)
	calls := make(chan int, 3)
	go func() {
		n := 0
		runRouteRefresh(ctx, ticks, &activity, 0, func(context.Context) {
			n++
			if n == 1 {
				trackUserEvent(&activity, smartproxy.Event{OK: true})
			}
			calls <- n
		})
	}()
	for i := 1; i <= 2; i++ {
		ticks <- time.Now()
		select {
		case got := <-calls:
			if got != i {
				t.Fatal(got)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent user activity was discarded")
		}
	}
	// Results of already timed-out probes arrive after refresh has returned.
	if trackUserEvent(&activity, smartproxy.Event{Probe: true, OK: true}) {
		t.Fatal("late probe admitted to user feed")
	}
	if trackUserEvent(&activity, smartproxy.Event{Probe: true, Err: "late timeout"}) {
		t.Fatal("late failed probe counted as user activity")
	}
	ticks <- time.Now()
	select {
	case <-calls:
		t.Fatal("late probe kept an idle session active")
	case <-time.After(30 * time.Millisecond):
	}
}
