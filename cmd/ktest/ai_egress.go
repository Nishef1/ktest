package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

// probeForeignExit requests a small, publicly verifiable egress trace THROUGH
// the individual SOCKS exit. This prevents treating local SOCKS readiness or a
// successful TLS handshake as proof that an AI request leaves outside Iran.
// This is an initial GeoIP hint, not a permanent static-IP guarantee.
func probeForeignExit(parent context.Context, socks string) (ip, country string, err error) {
	ip, country, err = probeExitLocation(parent, socks)
	if err != nil {
		return ip, country, err
	}
	return parseForeignTrace("ip=" + ip + "\nloc=" + country)
}

func probeExitLocation(parent context.Context, socks string) (ip, country string, err error) {
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	tr := &http.Transport{
		Proxy:                  nil,
		MaxResponseHeaderBytes: 32 << 10,
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    8 * time.Second,
		ResponseHeaderTimeout:  8 * time.Second,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return smartproxy.DialVia(ctx, socks, "www.cloudflare.com", "443", 8*time.Second)
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 11 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.cloudflare.com/cdn-cgi/trace", nil)
	if e != nil {
		return "", "", e
	}
	resp, e := client.Do(req)
	if e != nil {
		return "", "", fmt.Errorf("foreign exit geo-check failed: %w", e)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("foreign exit geo-check HTTP %d", resp.StatusCode)
	}
	data, e := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if e != nil {
		return "", "", e
	}
	if len(data) > 4096 {
		return "", "", errors.New("unexpected geo-check response")
	}
	return parseExitTrace(string(data))
}

func parseForeignTrace(body string) (ip, country string, err error) {
	ip, country, err = parseExitTrace(body)
	if err != nil {
		return ip, country, err
	}
	if country == "IR" || country == "RU" {
		return ip, country, fmt.Errorf("egress location %q is blocked under the AI exit policy", country)
	}
	return ip, country, nil
}

func parseExitTrace(body string) (ip, country string, err error) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ip=") {
			ip = strings.TrimPrefix(line, "ip=")
		}
		if strings.HasPrefix(line, "loc=") {
			country = strings.ToUpper(strings.TrimPrefix(line, "loc="))
		}
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || !parsed.IsGlobalUnicast() || parsed.IsPrivate() {
		return "", "", errors.New("geo-check did not return a public egress IP")
	}
	if len(country) != 2 || country == "XX" || country == "ZZ" || country == "T1" || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
		return ip, country, fmt.Errorf("egress location %q is blocked or unknown under the exit policy", country)
	}
	return ip, country, nil
}
