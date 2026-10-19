package edges

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/cdnranges"
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
	if limit == 0 && strings.EqualFold(strings.TrimSpace(provider), "cloudflare") {
		return Preset{}, errors.New("continuous Cloudflare scans require ScanCandidateSource")
	}
	preset, next, err := ScanCandidateSource(ctx, provider, limit)
	if err != nil {
		return Preset{}, err
	}
	preset.IPs = nil
	for {
		ip, ok, err := next(ctx)
		if err != nil {
			return Preset{}, err
		}
		if !ok {
			return preset, nil
		}
		preset.IPs = append(preset.IPs, ip)
	}
}

// prefixOverride replaces a provider's inventory in tests.
var prefixOverride map[string][]string

// prefixesFor is the provider's complete IPv4 inventory: the refreshed
// cdnranges cache or its embedded snapshot.
func prefixesFor(provider string) []string {
	if p, ok := prefixOverride[provider]; ok {
		return p
	}
	if r := cdnranges.Current().Providers[provider]; r != nil && len(r.V4) > 0 {
		return r.V4
	}
	if provider == "cloudflare" {
		return cloudflareIPv4
	}
	return nil
}

func inventorySize(prefixes []string) int {
	inventory := 0
	for _, raw := range prefixes {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			continue
		}
		size := 1 << uint(32-p.Bits())
		if size >= 256 {
			inventory += size / 256 * 254
		} else if size > 2 {
			inventory += size - 2
		} else {
			inventory += size
		}
	}
	return inventory
}

// ScanCandidateSource streams a provider's candidates lazily: first the
// source-attributed seeds (known edges, fresh DNS answers), then every
// address of the provider's own published or ASN-announced inventory.
func ScanCandidateSource(ctx context.Context, provider string, budget int) (Preset, CandidateIterator, error) {
	if budget < 0 {
		return Preset{}, nil, errors.New("candidate budget must be nonnegative")
	}
	if err := ctx.Err(); err != nil {
		return Preset{}, nil, err
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	preset, err := PresetCandidates(ctx, provider)
	if err != nil {
		return Preset{}, nil, err
	}
	prefixes := prefixesFor(provider)
	ranges, err := prefixIterator(prefixes, 0)
	if err != nil {
		return Preset{}, nil, err
	}
	seeds := preset.IPs
	preset.IPs = nil
	preset.InventorySize = len(seeds) + inventorySize(prefixes)
	if len(prefixes) > 0 {
		preset.Source = strings.TrimPrefix(preset.Source+"; ", "; ") + rangeSource(provider)
	}
	seen := map[string]bool{}
	emitted := 0
	return preset, func(ctx context.Context) (string, bool, error) {
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
		if budget > 0 && emitted >= budget {
			return "", false, nil
		}
		for len(seeds) > 0 {
			ip := seeds[0]
			seeds = seeds[1:]
			if !seen[ip] {
				seen[ip] = true
				emitted++
				return ip, true, nil
			}
		}
		for {
			ip, ok, err := ranges(ctx)
			if err != nil || !ok {
				return "", ok, err
			}
			if seen[ip] {
				continue
			}
			emitted++
			return ip, true, nil
		}
	}, nil
}

func rangeSource(provider string) string {
	if r := cdnranges.Current().Providers[provider]; r != nil && r.Source != "" {
		return r.Source + " (updated " + r.Updated.Format("2006-01-02") + ")"
	}
	return "built-in provider ranges"
}

var presetURLs = map[string]string{
	"cloudflare": "https://www.cloudflare.com/cdn-cgi/trace",
	"akamai":     "https://a248.e.akamai.net/",
	"fastly":     "https://pypi.org/",
	"google":     "https://fonts.googleapis.com/",
	"meta":       "https://www.facebook.com/",
	"cloudfront": "https://aws.amazon.com/robots.txt",
	"gcore":      "https://gcore.com/robots.txt",
}

// PresetCandidates selects the small source-backed seed set that is tried
// before the provider's inventory. Reachability, TLS trust, CDN routing and
// filtering outcomes are established separately.
func PresetCandidates(ctx context.Context, provider string) (Preset, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	target, ok := presetURLs[provider]
	if !ok {
		return Preset{}, errors.New("choose " + strings.Join(cdnranges.Providers, ", "))
	}
	preset := Preset{Provider: provider, URL: target, UpdatedUTC: time.Now().UTC().Format(time.RFC3339),
		Origin: "Provider-owned candidate IPs; successful TLS is not proof of working fronting"}
	switch provider {
	case "cloudflare":
		preset.Source = "https://www.cloudflare.com/ips/"
		return preset, nil
	case "akamai":
		preset.IPs = []string{
			"92.123.102.43", "23.215.0.206", "23.215.0.203",
			"23.212.250.91", "23.212.250.78", "23.12.147.13",
			"23.12.147.29", "23.73.207.8",
		}
		preset.UpdatedUTC = "2026-10-05"
		preset.Source = "https://github.com/KNG7-P/Se7en-Pro/blob/master/Se7enPro/Services/CdnFrontingBuilder.cs"
		return preset, nil
	}
	u, _ := url.Parse(target)
	lookup, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(lookup, u.Hostname())
	if err != nil {
		// A filtered resolver only costs the seeds; the inventory remains.
		return preset, nil
	}
	seen := map[string]bool{}
	for _, v := range ips {
		ip, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		key := ip.String()
		// Only answers inside the provider's own inventory are seeds: a
		// poisoned resolver cannot inject a block-page address.
		if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || seen[key] || !inPrefixes(prefixesFor(provider), ip) {
			continue
		}
		seen[key] = true
		preset.IPs = append(preset.IPs, key)
	}
	sort.Strings(preset.IPs)
	preset.Source = "local DNS resolver for " + u.Hostname()
	return preset, nil
}

func inPrefixes(prefixes []string, ip netip.Addr) bool {
	for _, raw := range prefixes {
		if p, err := netip.ParsePrefix(raw); err == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}
