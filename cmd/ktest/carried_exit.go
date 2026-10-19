package main

import (
	"context"
	"strings"

	"github.com/Nishef1/ktest/internal/aether"
	"github.com/Nishef1/ktest/internal/cdnranges"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

// Psiphon and Tor need no WARP, so when WARP is down they are the exits left.
// Their own transports still dial from inside Iran, which is exactly what DPI
// filters, so Aether runs them with --upstream through the same local anti-DPI
// carrier (plain, Go desync, ByeDPI, Zapret) that Fast and the Aether H2
// profiles use. The exit-only proxy of these modes has no such routes, so the
// carrier is fed by a separate source proxy that never serves user traffic.

// maxPsiphonEdges bounds --psiphon-cdn-ips so the command line stays short.
const maxPsiphonEdges = 40

// psiphonEdgeProviders are the CDNs Psiphon fronts through, best first.
var psiphonEdgeProviders = []string{"akamai", "cloudflare", "fastly", "cloudfront"}

// carrierSourceUpstreams keeps only the routes a local carrier may use: no
// exit, no takeover, local bypass or direct. Anything else is dropped.
func carrierSourceUpstreams(ups []smartproxy.Upstream) []smartproxy.Upstream {
	var out []smartproxy.Upstream
	for _, u := range ups {
		if !u.Exit && u.Takeover == nil && (u.LocalBypass || (u.Addr == "" && u.Dial == nil)) {
			out = append(out, u)
		}
	}
	return out
}

// newCarrierSource builds the private proxy whose routes a Psiphon or Tor
// carrier inherits. It is nil when there is nothing to carry with.
func newCarrierSource(ups []smartproxy.Upstream, cfg smartproxy.Config) (*smartproxy.Proxy, error) {
	ups = carrierSourceUpstreams(ups)
	if len(ups) == 0 {
		return nil, nil
	}
	return smartproxy.New(smartproxy.Config{Upstreams: ups, Stagger: cfg.Stagger, FirstByteTimeout: cfg.FirstByteTimeout,
		HistoryFile: cfg.HistoryFile, HistoryKey: cfg.HistoryKey, Logf: cfg.Logf})
}

// carriesExit reports whether p is a standalone Psiphon or Tor backend that
// should dial through the local carrier instead of directly.
func carriesExit(p aetherProfile) bool {
	return (p.Psiphon() || p.Has("--tor-only")) && !p.Has("--upstream")
}

// withCarrier appends --upstream for an owned loopback carrier. The address is
// validated the same way as the H2 profiles' placeholder binding.
func withCarrier(args []string, carrier string) ([]string, error) {
	return aether.BindLocalCarrier(append(append([]string(nil), args...), "--upstream", aether.LocalCarrierURL), carrier)
}

// withPsiphonEdges adds CDN edges for Psiphon's fronting; its built-in lists
// still follow. Profiles that already pin edges keep their own.
func withPsiphonEdges(args []string, p aetherProfile, edges []string) []string {
	if !p.Psiphon() || p.Has("--psiphon-cdn-ips") || len(edges) == 0 {
		return args
	}
	return append(append([]string(nil), args...), "--psiphon-cdn-ips", strings.Join(edges, ","))
}

// psiphonCDNEdges samples the known inventories evenly across providers. No
// verified scan results are kept on Windows, so these are unverified samples;
// Psiphon tests each one itself and falls back to its own lists.
func psiphonCDNEdges(set *cdnranges.Set) []string {
	if set == nil {
		return nil
	}
	per := maxPsiphonEdges / len(psiphonEdgeProviders)
	samples := make([][]string, len(psiphonEdgeProviders))
	for i, provider := range psiphonEdgeProviders {
		samples[i] = set.Sample(provider, per)
	}
	seen := map[string]bool{}
	var out []string
	for i := 0; i < per; i++ {
		for _, s := range samples {
			if i < len(s) && !seen[s[i]] && len(out) < maxPsiphonEdges {
				seen[s[i]] = true
				out = append(out, s[i])
			}
		}
	}
	return out
}

// supportedPsiphonEdges returns edges only when this Aether build documents
// --psiphon-cdn-ips; an unknown flag would stop Psiphon from starting at all.
func supportedPsiphonEdges(ctx context.Context, bin string) []string {
	edges := psiphonCDNEdges(cdnranges.Current())
	if len(edges) == 0 {
		return nil
	}
	probe := aetherProfile{Label: "Psiphon edges", Args: []string{"--psiphon-only", "--psiphon-cdn-ips", edges[0]}}
	if ok, err := aether.InspectProfiles(ctx, bin, []aetherProfile{probe}); err != nil || len(ok) == 0 {
		return nil
	}
	return edges
}
