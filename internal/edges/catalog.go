package edges

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type Preset struct {
	Provider   string
	URL        string
	IPs        []string
	Origin     string
	UpdatedUTC string
	Source     string
}

// PresetCandidates only selects a small source-backed seed set. Reachability,
// TLS trust, CDN routing, and filtering outcomes are established separately.
func PresetCandidates(ctx context.Context, provider string) (Preset, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch provider {
	case "akamai":
		return Preset{
			Provider:   "akamai",
			URL:      "https://a248.e.akamai.net/",
			IPs: []string{
				"92.123.102.43", "23.215.0.206", "23.215.0.203",
				"23.212.250.91", "23.212.250.78", "23.12.147.13",
				"23.12.147.29", "23.73.207.8",
			},
			Origin:     "Unverified candidate IPs; do not treat successful TLS as working fronting",
			UpdatedUTC: "2026-10-05",
			Source:     "https://github.com/KNG7-P/Se7en-Pro/blob/master/Se7enPro/Services/CdnFrontingBuilder.cs",
		}, nil
	case "fastly", "google":
		hostname := "pypi.org"
		if provider == "google" {
			hostname = "fonts.googleapis.com"
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
		if err != nil {
			return Preset{}, fmt.Errorf("DNS bootstrap for %s: %w", hostname, err)
		}
		seen := map[string]bool{}
		candidates := make([]string, 0, 8)
		for _, v := range ips {
			ip, ok := netip.AddrFromSlice(v.IP)
			if !ok || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			key := ip.Unmap().String()
			if !seen[key] {
				candidates = append(candidates, key)
				seen[key] = true
			}
		}
		sort.Strings(candidates)
		if len(candidates) > 8 {
			candidates = candidates[:8]
		}
		if len(candidates) == 0 {
			return Preset{}, errors.New("resolver returned no usable addresses; do not trust a poisoned DNS result")
		}
		return Preset{
			Provider:   provider,
			URL:        "https://" + hostname + "/",
			IPs:        candidates,
			Origin:     "Fresh DNS answers, not a verified Fronting route",
			UpdatedUTC: time.Now().UTC().Format(time.RFC3339),
			Source:     "local DNS resolver for " + hostname,
		}, nil
	default:
		return Preset{}, errors.New("choose akamai, fastly, or google")
	}
}
