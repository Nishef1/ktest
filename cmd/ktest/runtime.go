package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/quickcheck"
)

// Local proxy ports the bundled cores listen on.
const (
	xrayPort   = 10808
	byeDPIPort = 10809
)

// portFree reports an actionable error when something already listens on the
// loopback port. Without this a foreign proxy (v2rayN also defaults to 10808
// and 10809) or an orphaned core would answer ktest's readiness probe and the
// website check would silently measure somebody else's proxy.
func portFree(port int) error {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fmt.Errorf("127.0.0.1:%d is already in use (another proxy such as v2rayN, or a previous xray/ciadpi still running); close it first, owner: netstat -ano | findstr :%d", port, port)
	}
	return l.Close()
}

// waitForPort polls until something accepts on the loopback port. It gives up
// when ctx ends, done closes (the core exited) or limit passes.
func waitForPort(ctx context.Context, done <-chan struct{}, port int, limit time.Duration) bool {
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	tick := time.NewTicker(120 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-done:
			return false
		case <-deadline.C:
			return false
		case <-tick.C:
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return true
			}
		}
	}
}

// measure runs the real HTTPS checks through the local SOCKS port and, in
// parallel, directly, so the two results are comparable.
func measure(ctx context.Context, port int) ([]quickcheck.Result, []quickcheck.Assessment) {
	checkCtx, cancel := context.WithTimeout(ctx, 24*time.Second)
	defer cancel()
	var direct []quickcheck.Result
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); direct = quickcheck.RunDirect(checkCtx, 8*time.Second) }()
	proxied := quickcheck.Run(checkCtx, port, 8*time.Second)
	wg.Wait()
	return proxied, quickcheck.Compare(proxied, direct)
}

// proxiedPassCount counts targets that worked through the proxy.
func proxiedPassCount(results []quickcheck.Result) int {
	n := 0
	for _, r := range results {
		if r.Success {
			n++
		}
	}
	return n
}
