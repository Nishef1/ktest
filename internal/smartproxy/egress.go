package smartproxy

import (
	"context"
	"fmt"
	"time"
)

func (p *Proxy) exitRequired(host string) bool {
	return p.cfg.ExitRequired != nil && p.cfg.ExitRequired(host)
}

// HasWorkingExit reports a registered exit that carries traffic, wherever it
// geolocates. Only HasVerifiedExit speaks for protected (AI) destinations.
func (p *Proxy) HasWorkingExit() bool {
	total, _ := p.ExitCounts()
	return total > 0
}

func (p *Proxy) verifyCarrier(ctx context.Context, u *upstreamState) error {
	if p.cfg.VerifyCarrier == nil {
		return fmt.Errorf("managed carrier verifier unavailable")
	}
	u.carrierMu.Lock()
	defer u.carrierMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if time.Now().Before(u.carrierUntil) {
		return nil
	}
	vctx, cancel := context.WithTimeout(ctx, p.cfg.ConnectTimeout)
	defer cancel()
	if err := p.cfg.VerifyCarrier(vctx, u.Upstream); err != nil {
		return fmt.Errorf("carrier verification failed: %w", err)
	}
	u.carrierUntil = time.Now().Add(p.cfg.ExitVerifyTTL)
	return nil
}

// Refresh only when protected traffic needs an expired lease. Concurrent
// requests share one check; a failed/unknown location never permits the dial.
func (p *Proxy) verifyExit(ctx context.Context, u *upstreamState) error {
	if p.cfg.VerifyExit == nil {
		return nil
	}
	u.verifyMu.Lock()
	defer u.verifyMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if time.Now().UnixNano() < u.verifiedUntil.Load() {
		return nil
	}
	// A frozen route may reverify its SAME already selected foreign exit.
	// This is a trust-lease refresh, not route calibration or a fallback.
	// Failure still blocks protected traffic; no direct socket is permitted.
	if time.Now().Before(u.retryAfter) {
		return u.verifyErr
	}
	vctx, cancel := context.WithTimeout(ctx, p.cfg.ConnectTimeout)
	defer cancel()
	if err := p.cfg.VerifyExit(vctx, u.Upstream); err != nil {
		u.verifyErr = fmt.Errorf("foreign exit verification expired and refresh failed: %w", err)
		u.retryAfter = time.Now().Add(5 * time.Second)
		return u.verifyErr
	}
	u.verifiedUntil.Store(time.Now().Add(p.cfg.ExitVerifyTTL).UnixNano())
	u.verifyErr, u.retryAfter = nil, time.Time{}
	return nil
}
