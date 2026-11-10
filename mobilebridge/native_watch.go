package mobilebridge

import (
	"context"
	"errors"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

// A managed Aether core can stay alive while its WARP tunnel is dead: after a
// network change or a dropped QUIC/WireGuard session the process still listens
// and still answers SOCKS, yet nothing it dials gets an answer. The VPN then
// reads "connected" and apps such as Telegram sit at "connecting" forever.
//
// The watchdog is traffic-driven so an idle phone is never woken: it acts only
// when the apps sent data toward the core and nothing came back. It then probes
// the core itself and, after repeated failures, ends the session so that the
// platform's automatic recovery builds a fresh one.
const (
	nativeWatchTick     = 15 * time.Second
	nativeWatchSilence  = 20 * time.Second // sent data this long ago with no answer
	nativeWatchRecent   = 60 * time.Second // ignore traffic older than this
	nativeWatchProbeFor = 10 * time.Second
	nativeWatchFailures = 2
)

// nativeStalled reports whether the application sent data toward the core
// recently without any answer newer than that data by at least `silence`.
func nativeStalled(lastUp, lastDown, now time.Time, silence, recent time.Duration) bool {
	if lastUp.IsZero() || now.Sub(lastUp) > recent {
		return false // idle: nothing is waiting for an answer
	}
	if !lastDown.IsZero() && !lastDown.Before(lastUp.Add(-silence)) {
		return false // answers keep pace with what was sent
	}
	return true
}

func superviseNativeLiveness(ctx context.Context, n *nativeCore, mode string,
	probe func(context.Context, string, string) (observedExit, error), onDead func()) {
	ticker := time.NewTicker(nativeWatchTick)
	defer ticker.Stop()
	failures, stalledTicks := 0, 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-n.done:
			return
		case <-ticker.C:
		}
		now := time.Now()
		stalled := nativeStalled(smartproxy.LastCoreUpstream(n.address), smartproxy.LastCoreDownstream(n.address),
			now, nativeWatchSilence, nativeWatchRecent)
		if !stalled {
			failures, stalledTicks = 0, 0
			continue
		}
		// One quiet tick is normal request latency; two in a row is not.
		if stalledTicks++; stalledTicks < 2 {
			continue
		}
		probeCtx, stop := context.WithTimeout(ctx, nativeWatchProbeFor)
		_, err := probe(probeCtx, mode, n.address)
		stop()
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return
		}
		if err == nil {
			failures, stalledTicks = 0, 0
			continue
		}
		failures++
		if failures >= nativeWatchFailures {
			onDead()
			return
		}
	}
}
