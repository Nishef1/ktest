package main

import (
	"context"
	"sync"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

// Local traffic can use the proxy immediately. Discovery, registration and
// neutral exit checks start only when a real connection exhausts local paths.
func startWarpOnDemand(parent context.Context, o connectOptions, p *smartproxy.Proxy, t *term, demand <-chan struct{}) (func() string, func()) {
	if o.noWarp || !fileOK(aetherBinary(o.base)) {
		return startWarp(parent, o, p, t)
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	var mu sync.RWMutex
	status := func() string { return "idle; local paths first, managed discovery on demand" }
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			return
		case <-demand:
		}
		mu.Lock()
		status = func() string { return "starting managed exit discovery" }
		mu.Unlock()
		current, stop := startWarp(ctx, o, p, t)
		defer stop()
		mu.Lock()
		status = current
		mu.Unlock()
		<-ctx.Done()
	}()
	return func() string { mu.RLock(); current := status; mu.RUnlock(); return current() }, func() { cancel(); <-done }
}
