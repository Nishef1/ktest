package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Nishef1/ktest/internal/byedpi"
	"github.com/Nishef1/ktest/internal/quickcheck"
)

// xrayPort is where Connect's main Xray profile listens.
const xrayPort = 10808

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

// waitForByeDPI requires the actual SOCKS5 no-auth handshake. Port-only
// readiness can accidentally accept a broken or unrelated TCP listener.
func waitForByeDPI(ctx context.Context, done <-chan struct{}, port int, limit time.Duration) bool {
	readyCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	return byedpi.WaitReady(readyCtx, done, fmt.Sprintf("127.0.0.1:%d", port))
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

// defaultBase finds the portable folder (the one holding cores/). The exe's
// own folder is right for the packaged build, but `go run` builds the exe in a
// temporary folder, so the working directory and ./dist/ktest-portable are
// tried too. KTEST_BASE overrides everything.
func defaultBase() string {
	if env := os.Getenv("KTEST_BASE"); env != "" {
		return env
	}
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wd, filepath.Join(wd, "dist", "ktest-portable"), filepath.Join(wd, "ktest-portable"))
	}
	for _, dir := range candidates {
		if info, err := os.Stat(filepath.Join(dir, "cores")); err == nil && info.IsDir() {
			return dir
		}
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return "."
}
