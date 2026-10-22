package edges

import (
	"context"
	"errors"
	"math/rand/v2"
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

// prefixOverride replaces a provider's IPv4 inventory in tests.
var prefixOverride map[string][]string
var prefixOverrideV6 map[string][]string

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

func prefixesForFamily(provider, family string) []string {
	if family == "ipv4" {
		return prefixesFor(provider)
	}
	if family != "ipv6" {
		return nil
	}
	if p, ok := prefixOverrideV6[provider]; ok {
		return p
	}
	if r := cdnranges.Current().Providers[provider]; r != nil {
		return r.V6
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

// ScanCandidateSource preserves the original IPv4-only API.
func ScanCandidateSource(ctx context.Context, provider string, budget int) (Preset, CandidateIterator, error) {
	return ScanCandidateSourceFamily(ctx, provider, budget, "ipv4")
}

// ScanCandidateSourceFamily streams candidates from one IP family. IPv6
// inventories are sampled rather than enumerated because provider prefixes
// contain far more addresses than a practical scan can exhaust.
func ScanCandidateSourceFamily(ctx context.Context, provider string, budget int, family string) (Preset, CandidateIterator, error) {
	if budget < 0 {
		return Preset{}, nil, errors.New("candidate budget must be nonnegative")
	}
	if err := ctx.Err(); err != nil {
		return Preset{}, nil, err
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	family = strings.ToLower(strings.TrimSpace(family))
	if family != "ipv4" && family != "ipv6" {
		return Preset{}, nil, errors.New("IP family must be ipv4 or ipv6")
	}
	preset, err := PresetCandidatesFamily(ctx, provider, family)
	if err != nil {
		return Preset{}, nil, err
	}
	prefixes := prefixesForFamily(provider, family)
	if family == "ipv6" && len(prefixes) == 0 {
		return Preset{}, nil, errors.New("provider has no IPv6 prefix inventory")
	}
	var ranges CandidateIterator
	if family == "ipv4" {
		ranges, err = prefixIterator(prefixes, 0)
	} else {
		rangeSet := &cdnranges.Set{Version: 1, Providers: map[string]*cdnranges.Range{
			provider: {V6: prefixes},
		}}
		ranges = rangeSet.IteratorIPv6(provider, budget, rand.Uint64()|1)
	}
	if err != nil {
		return Preset{}, nil, err
	}
	seeds := preset.IPs
	preset.IPs = nil
	if family == "ipv4" {
		preset.InventorySize = len(seeds) + inventorySize(prefixes)
	} else {
		size := inventorySizeV6(prefixes)
		maxInt := int(^uint(0) >> 1)
		if size > maxInt-len(seeds) {
			size = maxInt
		} else {
			size += len(seeds)
		}
		preset.InventorySize = size
	}
	if len(prefixes) > 0 {
		source := rangeSource(provider)
		if family == "ipv6" {
			source = "IPv6 " + source
		}
		preset.Source = strings.TrimPrefix(preset.Source+"; ", "; ") + source
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

func inventorySizeV6(prefixes []string) int {
	maxInt := int(^uint(0) >> 1)
	total := 0
	for _, raw := range prefixes {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() {
			continue
		}
		hostBits := 128 - p.Bits()
		if hostBits > 30 {
			return maxInt
		}
		size := 1 << uint(hostBits)
		if total > maxInt-size {
			return maxInt
		}
		total += size
	}
	return total
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

// PresetCandidates preserves the original IPv4 source policy.
func PresetCandidates(ctx context.Context, provider string) (Preset, error) {
	return PresetCandidatesFamily(ctx, provider, "ipv4")
}

// PresetCandidatesFamily selects source-backed seeds for one IP family. A
// resolver failure costs only the DNS seeds; the provider inventory remains.
func PresetCandidatesFamily(ctx context.Context, provider, family string) (Preset, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	family = strings.ToLower(strings.TrimSpace(family))
	if family != "ipv4" && family != "ipv6" {
		return Preset{}, errors.New("IP family must be ipv4 or ipv6")
	}
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
		preset.Source = "https://github.com/KNG7-P/Se7en-Pro/blob/master/Se7enPro/Services/CdnFrontingBuilder.cs"
		preset.UpdatedUTC = "2026-10-05"
		if family == "ipv4" {
			preset.IPs = []string{
				"92.123.102.43", "23.215.0.206", "23.215.0.203",
				"23.212.250.91", "23.212.250.78", "23.12.147.13",
				"23.12.147.29", "23.73.207.8",
			}
			return preset, nil
		}
	}
	u, _ := url.Parse(target)
	lookup, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(lookup, u.Hostname())
	if err != nil {
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
		familyMatch := family == "ipv4" && ip.Is4() || family == "ipv6" && ip.Is6() && !ip.Is4In6()
		if !familyMatch || !ip.IsGlobalUnicast() || ip.IsPrivate() || seen[key] ||
			!inPrefixes(prefixesForFamily(provider, family), ip) {
			continue
		}
		seen[key] = true
		preset.IPs = append(preset.IPs, key)
	}
	sort.Strings(preset.IPs)
	preset.Source = "local DNS resolver for " + u.Hostname() + " (" + family + ")"
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
