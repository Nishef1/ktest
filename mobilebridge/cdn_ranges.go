package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/Nishef1/ktest/internal/cdnranges"
)

type cdnRangesReport struct {
	Providers []cdnRangeProvider `json:"providers"`
	Stale     bool               `json:"stale"`
	Error     string             `json:"error,omitempty"`
}

type cdnRangeProvider struct {
	Name      string `json:"name"`
	Prefixes  int    `json:"prefixes"`
	Addresses int    `json:"addresses"`
	Updated   string `json:"updated"`
	Source    string `json:"source"`
	Refresh   string `json:"refresh,omitempty"`
}

func rangesHTTPClient(socks string) *http.Client {
	transport := &http.Transport{TLSHandshakeTimeout: 15 * time.Second}
	if socks != "" {
		proxy, _ := url.Parse("socks5h://" + socks)
		transport.Proxy = http.ProxyURL(proxy)
	}
	return &http.Client{Transport: transport, Timeout: 60 * time.Second}
}

func describeRanges(set *cdnranges.Set, reports []cdnranges.Report, err error) string {
	out := cdnRangesReport{Stale: set.Stale()}
	if err != nil {
		out.Error = err.Error()
	}
	notes := map[string]string{}
	for _, r := range reports {
		notes[r.Provider] = r.String()
	}
	for _, p := range cdnranges.Providers {
		r := set.Providers[p]
		if r == nil {
			continue
		}
		out.Providers = append(out.Providers, cdnRangeProvider{Name: p, Prefixes: len(r.V4) + len(r.V6), Addresses: set.Size(p),
			Updated: r.Updated.Format("2006-01-02"), Source: r.Source, Refresh: notes[p]})
	}
	raw, _ := json.Marshal(out)
	return string(raw)
}

// CDNRanges reports the complete CDN inventory used by scans and fronting.
func CDNRanges(privateFilesDir string) string {
	if !realPrivateDirectory(privateFilesDir) {
		return describeRanges(cdnranges.Current(), nil, errors.New("private files directory required"))
	}
	return describeRanges(cdnranges.Load(privateFilesDir), nil, nil)
}

// UpdateCDNRanges refreshes every provider from its official list (RIPEstat
// ASN data where none exists or it is blocked), directly and then through a
// running ktest session. Failed providers keep their previous inventory.
func UpdateCDNRanges(privateFilesDir string) (string, error) {
	if !realPrivateDirectory(privateFilesDir) {
		return "", errors.New("private files directory required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	reports, err := cdnranges.Refresh(ctx, rangesHTTPClient(""), privateFilesDir)
	if cdnranges.ReportsHaveFailures(reports) {
		if socks := activeSOCKS(); socks != "" {
			firstErr := err
			fallback, fallbackErr := cdnranges.Refresh(ctx, rangesHTTPClient(socks), privateFilesDir)
			reports = cdnranges.CombineReports(reports, fallback)
			if firstErr != nil {
				err = fallbackErr
			}
		}
	}
	return describeRanges(cdnranges.Current(), reports, err), err
}

func activeSOCKS() string {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	if activeProxy == nil || activeProxy.socks == nil {
		return ""
	}
	return activeProxy.socks.Addr().String()
}

// refreshRangesInBackground keeps the inventory current once a session is
// up, falling back to the session's own SOCKS listener when filtered.
func refreshRangesInBackground(ctx context.Context, privateFilesDir, socks string) {
	if !realPrivateDirectory(privateFilesDir) || !cdnranges.Load(privateFilesDir).Stale() {
		return
	}
	go func() {
		rctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		reports, err := cdnranges.Refresh(rctx, rangesHTTPClient(""), privateFilesDir)
		if cdnranges.ReportsHaveFailures(reports) && rctx.Err() == nil {
			_, _ = cdnranges.Refresh(rctx, rangesHTTPClient(socks), privateFilesDir)
		} else if err != nil {
			return
		}
	}()
}
