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
	Provider      string
	URL           string
	IPs           []string
	Origin        string
	UpdatedUTC    string
	Source        string
	InventorySize int // Actual source inventory before applying a scan budget.
}

// ScanCandidates is the candidate/source policy shared by CLI and Android.
func ScanCandidates(ctx context.Context, provider string, limit int) (Preset, error) {
	if limit < 0 {
		return Preset{}, errors.New("candidate budget must be nonnegative")
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "cloudflare" {
		if limit == 0 {
			return Preset{}, errors.New("continuous Cloudflare scans require ScanCandidateSource")
		}
		ips, err := CloudflareCandidates(limit)
		return Preset{Provider: provider, URL: "https://www.cloudflare.com/cdn-cgi/trace", IPs: ips,
			Source: "https://www.cloudflare.com/ips/", Origin: "Provider HTTPS candidates; arbitrary fronting is unverified"}, err
	}
	preset, err := PresetCandidates(ctx, provider)
	if err != nil {
		return Preset{}, err
	}
	if limit > 0 && len(preset.IPs) > limit {
		preset.IPs = preset.IPs[:limit]
	}
	return preset, nil
}

// ScanCandidateSource keeps Cloudflare's official range enumeration lazy.
// Other providers terminate at their actual attributed/DNS inventory; no new
// third-party prefixes or repeated DNS answers are invented to fill a budget.
func ScanCandidateSource(ctx context.Context, provider string, budget int) (Preset, CandidateIterator, error) {
	if budget < 0 {
		return Preset{}, nil, errors.New("candidate budget must be nonnegative")
	}
	if err := ctx.Err(); err != nil {
		return Preset{}, nil, err
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "cloudflare" {
		next, err := cloudflareIterator(budget)
		inventory := 0
		for _, raw := range cloudflareIPv4 {
			p, parseErr := netip.ParsePrefix(raw)
			if parseErr != nil {
				return Preset{}, nil, parseErr
			}
			size := 1 << uint(32-p.Bits())
			if size >= 256 {
				inventory += size / 256 * 254
			} else if size > 2 {
				inventory += size - 2
			}
		}
		return Preset{Provider: provider, URL: "https://www.cloudflare.com/cdn-cgi/trace",
			Source: "https://www.cloudflare.com/ips/", Origin: "Provider HTTPS only; target fronting is unverified", InventorySize: inventory}, next, err
	}
	preset, err := PresetCandidates(ctx, provider)
	if err != nil {
		return Preset{}, nil, err
	}
	preset.InventorySize = len(preset.IPs)
	i := 0
	return preset, func(ctx context.Context) (string, bool, error) {
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
		if i == len(preset.IPs) || (budget > 0 && i >= budget) {
			return "", false, nil
		}
		ip := preset.IPs[i]
		i++
		return ip, true, nil
	}, nil
}

// PresetCandidates only selects a small source-backed seed set. Reachability,
// TLS trust, CDN routing, and filtering outcomes are established separately.
func PresetCandidates(ctx context.Context, provider string) (Preset, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch provider {
	case "akamai":
		return Preset{
			Provider: "akamai",
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
