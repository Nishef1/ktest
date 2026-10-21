package main

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/Nishef1/ktest/internal/edges"
)

// frontEdgeProviders are the fronting families that take measured edges.
var frontEdgeProviders = []string{"cloudflare", "google", "fastly", "meta"}

// maxSavedPsiphonEdges leaves room in --psiphon-cdn-ips for inventory samples,
// since provider HTTPS on an edge does not prove Psiphon's own fronting works.
const maxSavedPsiphonEdges = 30

var errNoNetworkIdentity = errors.New("this network could not be identified")

func cdnEdgeDir() string {
	if warpDir() == "" {
		return ""
	}
	return filepath.Join(warpDir(), "cdn-scans")
}

// savedCDNEdges returns the provider edges `ktest scan` verified on this
// network within a day, fastest first. Without a network identity nothing is
// saved or reused: edges measured elsewhere are no better than samples.
func savedCDNEdges(network, provider string) []string {
	if network == "" {
		return nil
	}
	return edges.LoadVerified(cdnEdgeDir(), provider, network)
}

// saveCDNScan keeps a scan's verified results for this network.
func saveCDNScan(network, provider, source string, results []edges.ScanResult) error {
	if network == "" {
		return errNoNetworkIdentity
	}
	return edges.SaveVerified(cdnEdgeDir(), edges.VerifiedCache{Provider: provider, Network: network, Source: source, Results: results})
}

// frontPreferredEdges gives domain fronting this network's verified edges per
// family; the fronter still verifies each target before using one.
func frontPreferredEdges(ctx context.Context) map[string][]string {
	network := networkSignature(ctx)
	preferred := map[string][]string{}
	for _, provider := range frontEdgeProviders {
		if ips := savedCDNEdges(network, provider); len(ips) > 0 {
			preferred[provider] = ips
		}
	}
	return preferred
}

// withSavedPsiphonEdges puts this network's verified edges first, taken in
// turn from each Psiphon provider, then the samples; Psiphon's built-in lists
// still follow whatever is passed.
func withSavedPsiphonEdges(network string, samples []string) []string {
	saved := make([][]string, len(psiphonEdgeProviders))
	for i, provider := range psiphonEdgeProviders {
		saved[i] = savedCDNEdges(network, provider)
	}
	seen := map[string]bool{}
	var out []string
	for i := 0; len(out) < maxSavedPsiphonEdges; i++ {
		more := false
		for _, s := range saved {
			if i < len(s) {
				more = true
				if !seen[s[i]] && len(out) < maxSavedPsiphonEdges {
					seen[s[i]] = true
					out = append(out, s[i])
				}
			}
		}
		if !more {
			break
		}
	}
	for _, ip := range samples {
		if len(out) == maxPsiphonEdges {
			break
		}
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}

// withSavedCloudflareEdges puts this network's verified Cloudflare edges ahead
// of the scan candidates, so a Windscribe CDN route tries them first.
func withSavedCloudflareEdges(network string, candidates []string) []string {
	saved := savedCDNEdges(network, "cloudflare")
	if len(saved) == 0 {
		return candidates
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(saved)+len(candidates))
	for _, ip := range append(saved, candidates...) {
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}
