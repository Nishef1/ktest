package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"runtime"

	"github.com/Nishef1/ktest/internal/packetdesync"
	"github.com/Nishef1/ktest/internal/systemtun"
)

// wsPacketDesync serializes outer TLS/WebSocket handshakes. A filter exists
// only until that handshake ends; established OpenVPN streams need no filter.
// A failed cleanup prevents starting any further filters in this session.
type wsPacketDesync struct {
	gate    chan struct{}
	start   func(context.Context, string) (func() error, error)
	blocked error // protected by gate
}

func checkWindscribeZapret(base string) error {
	if runtime.GOOS != "windows" || !systemtun.IsAdmin() {
		return errors.New("Zapret2 needs Windows Terminal explicitly opened as Administrator")
	}
	return packetdesync.VerifyBundle(filepath.Join(base, "cores", "zapret2"))
}

func newWSPacketDesync(base, strategy string, note func(string, ...any)) *wsPacketDesync {
	return &wsPacketDesync{gate: make(chan struct{}, 1), start: func(ctx context.Context, ip string) (func() error, error) {
		note("Zapret2 %s: preparing Windscribe entry %s:443 (outer handshake only)", strategy, ip)
		logs := &tailBuffer{max: 4096}
		trial, err := packetdesync.Start(ctx, base, ip, packetdesync.Strategy(strategy), logs)
		if err != nil {
			if detail := logs.lastLine(); detail != "" {
				err = fmt.Errorf("%w: %s", err, trimDetail(detail))
			}
			return nil, err
		}
		return trial.Stop, nil
	}}
}

func (p *wsPacketDesync) open(ctx context.Context, ip string, open func() (net.Conn, error)) (net.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case p.gate <- struct{}{}:
	}
	defer func() { <-p.gate }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.blocked != nil {
		return nil, p.blocked
	}
	stop, err := p.start(ctx, ip)
	if err != nil {
		// Startup may have failed during driver/process cleanup. Do not
		// launch a second filter without a fresh, explicit session.
		p.blocked = fmt.Errorf("Zapret2 did not start; restart the session after checking the cause: %w", err)
		return nil, p.blocked
	}
	conn, dialErr := open()
	if cleanupErr := stop(); cleanupErr != nil {
		p.blocked = fmt.Errorf("Zapret2 cleanup unconfirmed; stop this session and check WinDivert: %w", cleanupErr)
		if conn != nil {
			_ = conn.Close()
		}
		return nil, errors.Join(dialErr, p.blocked)
	}
	return conn, dialErr
}

func (b *wsBridge) openCarrier(ctx context.Context, host, port string, c wsCarrier) (net.Conn, error) {
	if !b.opts.packetEnabled() {
		return c.open(ctx, host, port)
	}
	ip, carrierPort, err := net.SplitHostPort(c.addr)
	if err != nil || port != "443" || carrierPort != "443" || b.packet == nil {
		return nil, errors.New("Zapret2 requires a prepared controller and an exact provider TCP 443 entry")
	}
	verified := false
	for _, endpoint := range b.catalog.endpoints(host) {
		if endpoint.ip == ip {
			verified = true
			break
		}
	}
	if !verified {
		return nil, errors.New("Zapret2 refused an entry without a fresh mapping to Windscribe's requested TCP node")
	}
	if _, _, err := packetdesync.Target(ip, packetdesync.Strategy(b.opts.zapret)); err != nil {
		return nil, err
	}
	return b.packet.open(ctx, ip, func() (net.Conn, error) { return c.open(ctx, host, port) })
}
