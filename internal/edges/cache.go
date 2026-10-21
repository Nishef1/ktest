package edges

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/cdnranges"
	"github.com/Nishef1/ktest/internal/probe"
)

// Verified provider edges are preconnection candidates for a day; a scan of
// at most this many fastest edges is kept per provider and network.
const (
	VerifiedTTL      = 24 * time.Hour
	maxVerified      = 100
	maxVerifiedBytes = 128 * 1024
)

// ScanResult is one scan measurement: only timings and fixed error categories,
// never response content, headers, resolver diagnostics, URLs, or raw errors.
type ScanResult struct {
	IP           string `json:"ip"`
	TCPMS        int64  `json:"tcp_ms"`
	TLSMS        int64  `json:"tls_ms"`
	ElapsedMS    int64  `json:"elapsed_ms"`
	HTTPStatus   int    `json:"http_status"`
	TLSVerified  bool   `json:"tls_verified"`
	HTTPVerified bool   `json:"http_verified"`
	Assessment   string `json:"assessment"`
	Error        string `json:"error"`
}

// ResultOf summarizes a probe of ip as a ScanResult.
func ResultOf(ip string, r probe.Result) ScanResult {
	result := ScanResult{IP: ip, TCPMS: r.ConnectMS, TLSMS: r.TLSMS, ElapsedMS: r.ElapsedMS,
		HTTPStatus: r.Status, TLSVerified: r.TLSVersion != ""}
	if r.Error != "" {
		err := strings.ToLower(r.Error)
		switch {
		case strings.Contains(err, "canceled"):
			result.Error = "canceled"
		case strings.Contains(err, "timeout"), strings.Contains(err, "deadline exceeded"):
			result.Error = "timeout"
		case strings.Contains(err, "x509"), strings.Contains(err, "certificate"):
			result.Error = "certificate verification failed"
		case strings.Contains(err, "tls"):
			result.Error = "TLS failed"
		case strings.Contains(err, "connection refused"):
			result.Error = "connection refused"
		case strings.Contains(err, "connection reset"):
			result.Error = "connection reset"
		default:
			result.Error = "probe failed"
		}
	}
	result.HTTPVerified = r.Success && result.TLSVerified && r.Status >= 200 && r.Status < 300 && result.Error == ""
	switch {
	case result.HTTPVerified:
		result.Assessment = "provider_https_verified"
	case result.Error == "canceled":
		result.Assessment = "canceled"
	case result.TLSVerified:
		result.Assessment = "tls_only"
	case r.Reachable || r.Phase == "tls" || r.Phase == "http" || r.Phase == "tls_or_http":
		result.Assessment = "tcp_only"
	default:
		result.Assessment = "unreachable"
	}
	return result
}

// VerifiedCache is the saved scan of one provider on one network. Network is
// an opaque lowercase-hex key; empty means "any network" (Android's cache).
type VerifiedCache struct {
	Provider   string       `json:"provider"`
	Network    string       `json:"network,omitempty"`
	Source     string       `json:"source"`
	VerifiedAt time.Time    `json:"verified_at"`
	Results    []ScanResult `json:"results"`
}

func verifiedPath(dir, provider, network string) (string, bool) {
	if dir == "" || !cdnranges.Known(provider) || len(network) > 64 {
		return "", false
	}
	for _, c := range network {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	name := "verified-" + provider
	if network != "" {
		name += "-" + network
	}
	return filepath.Join(dir, name+".json"), true
}

// SaveVerified keeps the fastest provider-HTTPS-verified results of a scan.
// Unverified results are dropped; a scan with none is not saved. Expired
// caches of other networks are removed so the directory stays small.
func SaveVerified(dir string, c VerifiedCache) error {
	path, ok := verifiedPath(dir, c.Provider, c.Network)
	if !ok || c.Source == "" {
		return errors.New("invalid verified edge cache")
	}
	var best []ScanResult
	for _, r := range c.Results {
		if r.HTTPVerified {
			best = append(best, r)
		}
	}
	if len(best) == 0 {
		return errors.New("no verified edges to save")
	}
	sort.SliceStable(best, func(i, j int) bool {
		if best[i].ElapsedMS != best[j].ElapsedMS {
			return best[i].ElapsedMS < best[j].ElapsedMS
		}
		return best[i].IP < best[j].IP
	})
	if len(best) > maxVerified {
		best = best[:maxVerified]
	}
	c.Results = best
	if c.VerifiedAt.IsZero() {
		c.VerifiedAt = time.Now().UTC()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "verified-*.partial")
	if err != nil {
		return err
	}
	defer func() { file.Close(); os.Remove(file.Name()) }()
	if err := json.NewEncoder(file).Encode(c); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	pruneVerified(dir)
	return nil
}

func pruneVerified(dir string) {
	old, _ := filepath.Glob(filepath.Join(dir, "verified-*.json"))
	for _, p := range old {
		if info, err := os.Lstat(p); err == nil && info.Mode().IsRegular() && time.Since(info.ModTime()) > VerifiedTTL {
			os.Remove(p)
		}
	}
}

// LoadVerified returns at most 100 provider-HTTPS-verified edges of this
// provider measured on this network within VerifiedTTL, fastest first. They
// are candidates only: callers still verify the actual target before use.
// A malformed, foreign or stale cache yields nothing.
func LoadVerified(dir, provider, network string) []string {
	path, ok := verifiedPath(dir, provider, network)
	if !ok {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxVerifiedBytes {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var cache VerifiedCache
	if json.NewDecoder(io.LimitReader(f, maxVerifiedBytes)).Decode(&cache) != nil || cache.Provider != provider || cache.Network != network ||
		cache.Source == "" || len(cache.Results) > maxVerified || cache.VerifiedAt.After(time.Now()) || time.Since(cache.VerifiedAt) > VerifiedTTL {
		return nil
	}
	ips := make([]string, 0, len(cache.Results))
	seen := map[string]bool{}
	for _, r := range cache.Results {
		ip, err := netip.ParseAddr(r.IP)
		if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || !r.HTTPVerified || !r.TLSVerified || r.HTTPStatus < 200 || r.HTTPStatus >= 300 || r.Error != "" || seen[ip.String()] {
			return nil
		}
		ips = append(ips, ip.String())
		seen[ip.String()] = true
	}
	return ips
}
