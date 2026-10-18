package main

import (
	"context"
	"fmt"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
	"github.com/Nishef1/ktest/internal/egresscheck"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

const torOnlyPort = 18991

func probeTorExit(ctx context.Context, socks string) error {
	return egresscheck.ProbeTorExit(ctx, socks)
}

// startTor boots the bundled Aether Tor-only feature, with bridge discovery
// handled by Aether itself. No WARP, Psiphon or non-Tor fallback is involved.
// Connections stay blocked until HTTPS-through-Tor and foreign egress succeed.
func startTor(ctx context.Context, o connectOptions, p *smartproxy.Proxy, t *term) (string, func()) {
	if o.exitSocks != "" {
		return "using explicitly supplied local Tor SOCKS; verified before use", func() {}
	}
	bin := aetherBinary(o.base)
	if !fileOK(bin) {
		return "Tor unavailable: Aether core not found; supply -exit-socks with a verified Tor SOCKS port", func() {}
	}
	if err := portFree(torOnlyPort); err != nil {
		return "Tor unavailable: " + err.Error(), func() {}
	}
	torCtx, cancel := context.WithCancel(ctx)
	rc := &runningCore{cancel: cancel, done: make(chan struct{})}
	logs := &tailBuffer{max: 8192}
	if o.verbose {
		logs.tee = t.w
	}
	args := []string{"--tor-only", "--bind", fmt.Sprintf("127.0.0.1:%d", torOnlyPort), "--log-level", "warn"}
	go func() { rc.err = aether.Run(torCtx, bin, args, logs); close(rc.done) }()
	verified := make(chan struct{})
	go func() {
		defer close(verified)
		if !waitForPort(torCtx, rc.done, torOnlyPort, 7*time.Minute) {
			return
		}
		if !exitCarries(torCtx, rc.done, torOnlyPort, 7*time.Minute) {
			return
		}
		socks := fmt.Sprintf("127.0.0.1:%d", torOnlyPort)
		if err := probeTorExit(torCtx, socks); err != nil {
			if torCtx.Err() == nil {
				t.Note("Tor identity check failed: %v", err)
			}
			return
		}
		ip, country, err := probeForeignExit(torCtx, socks)
		if err != nil {
			if torCtx.Err() == nil {
				t.Note("Tor exit geo-check failed: %v", err)
			}
			return
		}
		if torCtx.Err() != nil {
			return
		}
		if err := p.Add(smartproxy.Upstream{Name: "Tor-only", Addr: socks, Exit: true, AIEligible: true, Rank: 0}); err != nil {
			t.Note("Tor exit registration failed: %v", err)
			return
		}
		t.Line(toneOK, "Tor-only is available (%s, %s); managed traffic is Tor-only, never direct", ip, country)
	}()
	return "starting Tor-only; waiting for Tor circuit and verified external exit", func() {
		cancel()
		rc.stop()
		<-verified
	}
}
