package cdnranges

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// asns are the autonomous systems registered to each provider. Every one is
// rechecked against RIPEstat's registered holder before its prefixes count,
// so a reassigned number cannot leak someone else's network into the list.
var asns = map[string][]int{
	"cloudflare": {13335},
	"fastly":     {54113},
	"google":     {15169},
	"akamai": {20940, 16625, 12222, 21342, 21357, 21399, 33905, 34164, 35994, 18680,
		23454, 31107, 31108, 31109, 31110, 35993, 36183, 43639},
	"meta":  {32934},
	"gcore": {199524},
}

var holders = map[string]string{
	"cloudflare": "cloudflare", "fastly": "fastly", "google": "google", "akamai": "akamai",
	"meta": "facebook", "gcore": "g-core",
}

func get(ctx context.Context, client *http.Client, url string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ktest-cdnranges/1")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if s, ok := v.(*string); ok {
		*s = string(raw)
		return nil
	}
	return json.Unmarshal(raw, v)
}

func fetchProvider(ctx context.Context, client *http.Client, provider string) (*Range, error) {
	var raw []string
	var source string
	var err error
	switch provider {
	case "cloudflare":
		raw, err = cloudflareOfficial(ctx, client)
		source = "https://www.cloudflare.com/ips/"
	case "fastly":
		raw, err = fastlyOfficial(ctx, client)
		source = "https://api.fastly.com/public-ip-list"
	case "google":
		raw, err = googleOfficial(ctx, client)
		source = "https://www.gstatic.com/ipranges/goog.json minus cloud.json"
	case "cloudfront":
		raw, err = cloudfrontOfficial(ctx, client)
		source = "https://ip-ranges.amazonaws.com/ip-ranges.json (CLOUDFRONT)"
	case "gcore":
		raw, err = gcoreOfficial(ctx, client)
		source = "https://api.gcore.com/cdn/public-ip-list"
	case "akamai", "meta":
		err = errors.New("no official list")
	default:
		return nil, fmt.Errorf("unknown provider %q", provider)
	}
	if err != nil || len(raw) == 0 {
		if len(asns[provider]) == 0 {
			if err == nil {
				err = errors.New("empty list")
			}
			return nil, err
		}
		raw, err = announced(ctx, client, provider)
		source = fmt.Sprintf("RIPEstat announced prefixes of %s ASNs %v", provider, asns[provider])
		if err != nil {
			return nil, err
		}
	}
	v4, v6 := usable(raw)
	if len(v4) == 0 {
		return nil, errors.New("no usable IPv4 prefixes")
	}
	return &Range{V4: v4, V6: v6, Updated: time.Now().UTC(), Source: source}, nil
}

func cloudflareOfficial(ctx context.Context, client *http.Client) ([]string, error) {
	var out []string
	for _, u := range []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"} {
		var body string
		if err := get(ctx, client, u, &body); err != nil {
			return nil, err
		}
		out = append(out, strings.Fields(body)...)
	}
	return out, nil
}

func fastlyOfficial(ctx context.Context, client *http.Client) ([]string, error) {
	var list struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := get(ctx, client, "https://api.fastly.com/public-ip-list", &list); err != nil {
		return nil, err
	}
	return append(list.Addresses, list.IPv6Addresses...), nil
}

// Google's documented way to find its service (front end) addresses is the
// full Google list minus the Cloud customer list.
func googleOfficial(ctx context.Context, client *http.Client) ([]string, error) {
	type ranges struct {
		Prefixes []struct {
			IPv4 string `json:"ipv4Prefix"`
			IPv6 string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	var all, cloud ranges
	if err := get(ctx, client, "https://www.gstatic.com/ipranges/goog.json", &all); err != nil {
		return nil, err
	}
	if err := get(ctx, client, "https://www.gstatic.com/ipranges/cloud.json", &cloud); err != nil {
		return nil, err
	}
	customer := map[string]bool{}
	for _, p := range cloud.Prefixes {
		customer[p.IPv4+p.IPv6] = true
	}
	var out []string
	for _, p := range all.Prefixes {
		if v := p.IPv4 + p.IPv6; v != "" && !customer[v] {
			out = append(out, v)
		}
	}
	return out, nil
}

func cloudfrontOfficial(ctx context.Context, client *http.Client) ([]string, error) {
	var list struct {
		Prefixes []struct {
			Prefix  string `json:"ip_prefix"`
			Service string `json:"service"`
		} `json:"prefixes"`
		IPv6 []struct {
			Prefix  string `json:"ipv6_prefix"`
			Service string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := get(ctx, client, "https://ip-ranges.amazonaws.com/ip-ranges.json", &list); err != nil {
		return nil, err
	}
	var out []string
	for _, p := range list.Prefixes {
		if p.Service == "CLOUDFRONT" {
			out = append(out, p.Prefix)
		}
	}
	for _, p := range list.IPv6 {
		if p.Service == "CLOUDFRONT" {
			out = append(out, p.Prefix)
		}
	}
	return out, nil
}

func gcoreOfficial(ctx context.Context, client *http.Client) ([]string, error) {
	var list struct {
		Addresses   []string `json:"addresses"`
		AddressesV6 []string `json:"addresses_v6"`
	}
	if err := get(ctx, client, "https://api.gcore.com/cdn/public-ip-list", &list); err != nil {
		return nil, err
	}
	return append(list.Addresses, list.AddressesV6...), nil
}

// announced unions the prefixes announced by the provider's ASNs, each
// confirmed to be registered to the provider.
func announced(ctx context.Context, client *http.Client, provider string) ([]string, error) {
	var mu sync.Mutex
	var out []string
	var firstErr error
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, asn := range asns[provider] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var overview struct {
				Data struct {
					Holder string `json:"holder"`
				} `json:"data"`
			}
			err := get(ctx, client, fmt.Sprintf("https://stat.ripe.net/data/as-overview/data.json?resource=AS%d", asn), &overview)
			if err == nil && !strings.Contains(strings.ToLower(overview.Data.Holder), holders[provider]) {
				err = fmt.Errorf("AS%d is registered to %q", asn, overview.Data.Holder)
			}
			var prefixes struct {
				Data struct {
					Prefixes []struct {
						Prefix string `json:"prefix"`
					} `json:"prefixes"`
				} `json:"data"`
			}
			if err == nil {
				err = get(ctx, client, fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d", asn), &prefixes)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			for _, p := range prefixes.Data.Prefixes {
				out = append(out, p.Prefix)
			}
		}()
	}
	wg.Wait()
	if len(out) == 0 {
		if firstErr == nil {
			firstErr = errors.New("no announced prefixes")
		}
		return nil, firstErr
	}
	return out, nil
}
