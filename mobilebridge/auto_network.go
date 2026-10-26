package mobilebridge

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/cdnranges"
	"github.com/Nishef1/ktest/internal/edges"
	"github.com/Nishef1/ktest/internal/probe"
)

// Connection optimization is opportunistic: it never replaces a user DNS
// override, TLS fingerprint or fragment override. The existing encrypted DNS
// inventory and live Go routing measurements choose those transports. CDN
// provider HTTPS is a candidate, NOT proof of usable domain fronting.
const autoEdgeBudget = 5 * time.Second

var autoEdgeMu sync.Mutex
var autoEdgeLast = map[string]time.Time{}

func cdnCacheNetwork() string {
	if currentRouteNetworkToken() == "" {
		return ""
	}
	return routeNetworkHash()
}

func autoEdgeEligible(mode, dir string) bool {
	return (mode == "balanced" || mode == "fast" || mode == "psiphon") &&
		realPrivateDirectory(dir) && cdnCacheNetwork() != ""
}

// reserveEdgeScan limits retries when every provider is blocked. A retry is
// allowed on another underlying network or after the cooldown.
func reserveEdgeScan(network, provider string, now time.Time) bool {
	autoEdgeMu.Lock()
	defer autoEdgeMu.Unlock()
	key := network + ":" + provider
	if now.Sub(autoEdgeLast[key]) < 15*time.Minute {
		return false
	}
	autoEdgeLast[key] = now
	return true
}

func autoPrepareNetworkEdges(parent context.Context, dir, mode string) {
	if !autoEdgeEligible(mode, dir) || parent.Err() != nil {
		return
	}
	scanMu.Lock()
	manualScan := scanState.Running
	scanMu.Unlock()
	if manualScan {
		return
	}
	network := cdnCacheNetwork()
	scanDir := filepath.Join(dir, "cdn-scans")
	cdnranges.Load(dir)
	ctx, cancel := context.WithTimeout(parent, autoEdgeBudget)
	defer cancel()
	var wg sync.WaitGroup
	// Two independent providers, at most 12 addresses each. Other CDN
	// families retain their normal on-demand native fallback.
	for _, provider := range []string{"cloudflare", "fastly"} {
		if len(edges.LoadVerified(scanDir, provider, network)) > 0 ||
			!reserveEdgeScan(network, provider, time.Now()) {
			continue
		}
		wg.Add(1)
		go func(provider string) {
			defer wg.Done()
			preset, next, err := edges.ScanCandidateSourceFamily(ctx, provider, 12, "ipv4")
			if err != nil || ctx.Err() != nil {
				return
			}
			var best []edges.ScanResult
			_, _ = edges.ScanCDNStream(ctx, next, preset.URL, 2, probe.Run,
				func(ip string, result probe.Result, _, _ int) {
					if record := edges.ResultOf(ip, result); record.HTTPVerified {
						best = append(best, record)
					}
				})
			if len(best) > 0 && parent.Err() == nil {
				_ = edges.SaveVerified(scanDir, edges.VerifiedCache{
					Provider: provider, Network: network, Source: preset.Source,
					VerifiedAt: time.Now().UTC(), Results: best,
				})
			}
		}(provider)
	}
	wg.Wait()
}
