package smartproxy

import (
	"context"
	"fmt"
	"time"
)

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
