package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/packetdesync"
	"github.com/Nishef1/ktest/internal/wstunnel"
)

// A/B trials are deliberately SERIAL. WinDivert filters apply system-wide to
// the exact destination, and are not a separate SOCKS or VPN carrier.
func runWindscribeZapretCompare(ctx context.Context, u *term, base string, endpoints []wsEndpoint, sni string, rounds int, timeout time.Duration, strategy packetdesync.Strategy) int {
	if len(endpoints) == 0 {
		u.Line(toneFail, "Provider catalog supplied no verified entry")
		return 1
	}
	entry := net.JoinHostPort(endpoints[0].ip, "443")
	u.Heading("Zapret2 paired Windows test", "Same Windscribe entry + SNI. Baseline and packet-shaped trials run one at a time.")
	u.Note("Packet capture applies to OTHER processes accessing this same IP:443 while active; not a private ktest-only filter.")
	u.Note("Fixed entry=%s, SNI=%s, strategy=%s, rounds=%d; no login/route/DNS modifications", entry, sni, strategy, rounds)
	filter, _, err := packetdesync.Target(endpoints[0].ip, strategy)
	if err != nil {
		u.Line(toneFail, "Unsafe Zapret2 target: %v", err)
		return 2
	}
	u.Note("Kernel interception filter: %s", filter)
	logs := &tailBuffer{max: 4096}
	scoreBase, scoreZapret := 0, 0
	for i := range rounds {
		if ctx.Err() != nil {
			u.Line(toneWarn, "Comparison interrupted; incomplete pairs are inconclusive")
			return 1
		}
		cfg := wstunnel.Config{Addr: entry, Host: endpoints[0].ip, SNI: sni, Dial: directDial, Timeout: timeout, VerifyPeer: windscribeServerCert}
		before := probeWSCarrier(ctx, "wstunnel", cfg)
		if before.websocket {
			scoreBase++
		}
		u.Note("Pair %d/%d without Zapret2: TCP=%t TLS=%t WS101=%t stage=%s (%s)", i+1, rounds, before.tcp, before.tls, before.websocket, before.stage, before.failure)
		// Do not run the modified trial after a canceled or interrupted
		// baseline. Every launched filter must be owned and stopped.
		if ctx.Err() != nil {
			return 1
		}
		trial, err := packetdesync.Start(ctx, base, endpoints[0].ip, strategy, logs)
		if err != nil {
			u.Line(toneFail, "Zapret2 did not start: %v", err)
			if line := logs.lastLine(); line != "" {
				u.Note("winws2: %s", trimDetail(line))
			}
			return 1
		}
		after := probeWSCarrier(ctx, "wstunnel", cfg)
		cleanupErr := trial.Stop()
		if after.websocket {
			scoreZapret++
		}
		u.Note("Pair %d/%d with Zapret2: TCP=%t TLS=%t WS101=%t stage=%s (%s)", i+1, rounds, after.tcp, after.tls, after.websocket, after.stage, after.failure)
		if cleanupErr != nil {
			u.Line(toneFail, "Zapret2 cleanup unconfirmed: %v. Check the running process and WinDivert handle.", cleanupErr)
			return 1
		}
		if ctx.Err() != nil {
			u.Line(toneWarn, "Test canceled; do not interpret the partial comparison as success")
			return 1
		}
	}
	u.Heading("Paired result", fmt.Sprintf("WS101 baseline %d/%d; Zapret2 %d/%d", scoreBase, rounds, scoreZapret, rounds))
	switch {
	case scoreZapret > scoreBase:
		u.Note("Zapret2 improved the outer WebSocket reachability on this trial. Repeat before making a compatibility claim.")
	case scoreZapret < scoreBase:
		u.Line(toneWarn, "Zapret2 regressed this carrier; do not use this strategy on the current network")
	default:
		u.Note("No measured WebSocket improvement; equal scores do not prove the DPI uses the same filtering")
	}
	u.Note("OpenVPN authentication, foreign exit, other ISP networks and persistent driver cleanup remain unverified by this TLS/WebSocket-only test.")
	if scoreZapret == 0 && scoreBase == 0 {
		return 1
	}
	return 0
}

func zapretOptionValid(option string) bool {
	switch strings.TrimSpace(option) {
	case "off", string(packetdesync.Fake), string(packetdesync.Split):
		return true
	}
	return false
}
