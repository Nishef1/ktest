package main

import (
	"context"
	"fmt"
	"time"
)

// Idle sessions do not create periodic traffic. A live Windscribe VPN keeps
// ownership of its carrier; a failed independent probe must not tear it down.
func (m *warpManager) watchHealth(ctx context.Context, w *warpFound) {
	tick := time.NewTicker(3 * time.Minute)
	defer tick.Stop()
	last := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.rc.done:
			return
		case <-tick.C:
			if m.monitor != nil && m.monitor.Connected() {
				continue
			}
			activity := 0
			for _, s := range m.proxy.Stats() {
				activity += s.Wins + s.Failures
			}
			if activity == last {
				continue
			}
			last = activity
			addr := fmt.Sprintf("127.0.0.1:%d", w.port)
			probe := probeForeignExit
			if !m.o.mode.exitOnly() || m.o.mode == ModeWindscribeAether || m.o.mode == ModeAether {
				probe = probeExitLocation
			}
			if _, _, err := probe(ctx, addr); err == nil {
				continue
			}
			check, cancel := context.WithTimeout(ctx, 6*time.Second)
			_, _, err := probe(check, addr)
			cancel()
			if err == nil || ctx.Err() != nil {
				continue
			}
			r := measurementFor(w.p)
			r.State, r.Failure = "unhealthy", "active-route exit verification failed twice"
			_ = saveMeasurement(m.network, m.core, r)
			m.t.Line(toneWarn, "%s stopped passing exit checks; retiring it and trying saved alternatives. Protected AI identity remains pinned until you reconnect.", w.p.Label)
			w.rc.stop()
			return
		}
	}
}
