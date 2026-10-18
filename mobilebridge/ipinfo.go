package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Nishef1/ktest/internal/egresscheck"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

type publicIPReport struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Via     string `json:"via"` // "direct" or "connection"
}

// traceHosts are tried concurrently; any one answering is enough.
var traceHosts = []struct{ host, addr string }{
	{"one.one.one.one", "1.1.1.1:443"},
	{"www.cloudflare.com", ""},
	{"cloudflare-dns.com", "1.0.0.1:443"},
}

// PublicIP reports the public IP and country seen by Cloudflare. With
// viaConnection it goes through the running proxy's own SOCKS listener (the
// route apps actually use); otherwise it uses the current Android network.
func PublicIP(viaConnection bool) (string, error) {
	socks := ""
	if viaConnection {
		proxyMu.Lock()
		if activeProxy != nil {
			socks = activeProxy.socks.Addr().String()
		}
		proxyMu.Unlock()
		if socks == "" {
			return "", errors.New("not connected")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	type result struct {
		ip, country string
		err         error
	}
	results := make(chan result, len(traceHosts))
	for _, t := range traceHosts {
		go func() {
			ip, country, err := fetchTrace(ctx, t.host, t.addr, socks)
			results <- result{ip, country, err}
		}()
	}
	var lastErr error
	for range traceHosts {
		r := <-results
		if r.err != nil {
			lastErr = r.err
			continue
		}
		via := "direct"
		if viaConnection {
			via = "connection"
		}
		raw, err := json.Marshal(publicIPReport{IP: r.ip, Country: r.country, Via: via})
		return string(raw), err
	}
	return "", fmt.Errorf("public IP check failed: %w", lastErr)
}

func fetchTrace(ctx context.Context, host, addr, socks string) (string, string, error) {
	tr := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10,
		TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 8 * time.Second,
		DialContext: func(ctx context.Context, _, a string) (net.Conn, error) {
			target := a
			if addr != "" {
				target = addr
			}
			if socks != "" {
				// Name, not IP, so the session routes it like any app request.
				return smartproxy.DialVia(ctx, socks, host, "443", 8*time.Second)
			}
			return (&net.Dialer{Timeout: 6 * time.Second}).DialContext(ctx, "tcp", target)
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 11 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/cdn-cgi/trace", nil)
	if err != nil {
		return "", "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("%s: HTTP %d", host, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", "", err
	}
	ip, country, err := egresscheck.ParseExitTrace(string(body))
	if ip != "" && country != "" {
		return ip, country, nil // any country is fine for display
	}
	return "", "", err
}
