package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

const torOnlyPort = 18991

// A SOCKS server on a local port is not proof that it carries Tor.
// check.torproject.org is queried THROUGH the proxy and over verified HTTPS.
func probeTorExit(parent context.Context, socks string) error {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	tr := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return smartproxy.DialVia(ctx, socks, "check.torproject.org", "443", 10*time.Second)
		},
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://check.torproject.org/api/ip", nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Transport: tr, Timeout: 14 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("Tor status request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Tor status HTTP %d", resp.StatusCode)
	}
	var v struct {
		IsTor bool
		IP    string
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&v); err != nil {
		return err
	}
	if !v.IsTor {
		return errors.New("exit is not verified as Tor by the Tor Project")
	}
	return nil
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
	l := aetherLauncher(bin, []string{"--tor-only", "--bind", fmt.Sprintf("127.0.0.1:%d", torOnlyPort), "--log-level", "warn"}, logs)
	go func() { rc.err = l(torCtx, nil); close(rc.done) }()
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
