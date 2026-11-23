package egresscheck

import (
	"context"
	"encoding/json"
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
func ProbeForeignExit(parent context.Context, socks string) (ip, country string, err error) {
	ip, country, err = ProbeExitLocation(parent, socks)
	if err != nil {
		return ip, country, err
	}
	return ParseForeignTrace("ip=" + ip + "\nloc=" + country)
}

func ProbeExitLocation(parent context.Context, socks string) (ip, country string, err error) {
	return ProbeExitLocationFamily(parent, socks, "both")
}

// ProbeExitLocationFamily races a small independent provider inventory.
// Family-specific hostnames and validation of the observed address avoid
// mistaking an IPv4 result for IPv6. A filtered provider is not a failed tunnel.
func ProbeExitLocationFamily(parent context.Context, socks, family string) (ip, country string, err error) {
	if family == "" {
		family = "both"
	}
	if family != "both" && family != "ipv4" && family != "ipv6" {
		return "", "", errors.New("invalid egress IP family")
	}
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	host := "get.geojs.io"
	if family != "both" {
		host = family + ".geojs.io"
	}
	type result struct {
		ip, country string
		err         error
	}
	type target struct {
		host, path, format string
	}
	targets := []target{
		{host, "/v1/ip/country.json", "geojs"},
		{"ipapi.co", "/json/", "ipapi"},
		{"www.cloudflare.com", "/cdn-cgi/trace", "trace"},
	}
	results := make(chan result, len(targets))
	for i, t := range targets {
		go func() {
			timer := time.NewTimer(time.Duration(i) * 250 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				results <- result{err: ctx.Err()}
				return
			case <-timer.C:
			}
			ip, country, err := probeProvider(ctx, socks, t.host, t.path, t.format, family)
			results <- result{ip, country, err}
		}()
	}
	var last error
	for range targets {
		select {
		case <-ctx.Done():
			return "", "", fmt.Errorf("public IP verification unavailable: %w", ctx.Err())
		case r := <-results:
			if r.err == nil {
				return r.ip, r.country, nil
			}
			last = r.err
		}
	}
	return "", "", fmt.Errorf("all public IP providers unavailable: %w", last)
}

func ProbeForeignExitFamily(parent context.Context, socks, family string) (ip, country string, err error) {
	ip, country, err = ProbeExitLocationFamily(parent, socks, family)
	if err != nil {
		return ip, country, err
	}
	return ParseForeignTrace("ip=" + ip + "\nloc=" + country)
}

func probeProvider(ctx context.Context, socks, host, path, format, family string) (ip, country string, err error) {
	network := "tcp"
	if family == "ipv4" {
		network = "tcp4"
	} else if family == "ipv6" {
		network = "tcp6"
	}
	tr := &http.Transport{
		Proxy:                  nil,
		MaxResponseHeaderBytes: 32 << 10,
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    8 * time.Second,
		ResponseHeaderTimeout:  8 * time.Second,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			if socks != "" {
				return smartproxy.DialVia(ctx, socks, host, "443", 8*time.Second)
			}
			return (&net.Dialer{Timeout: 6 * time.Second}).DialContext(ctx, network, addr)
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 11 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path, nil)
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
	return parseProvider(data, format, family)
}

func ParseForeignTrace(body string) (ip, country string, err error) {
	ip, country, err = ParseExitTrace(body)
	if err != nil {
		return ip, country, err
	}
	if country == "IR" || country == "RU" {
		return ip, country, fmt.Errorf("egress location %q is not outside Iran", country)
	}
	return ip, country, nil
}

func ParseExitTrace(body string) (ip, country string, err error) {
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
	if parsed == nil || !parsed.IsGlobalUnicast() || smartproxy.Bogus(parsed) {
		return "", "", errors.New("geo-check did not return a public egress IP")
	}
	if len(country) != 2 || country == "XX" || country == "ZZ" || country == "T1" || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
		return ip, country, fmt.Errorf("egress location %q is blocked or unknown under the exit policy", country)
	}
	return ip, country, nil
}

// parseProvider validates every provider with the same public-address and
// country rules. The body is never used as a new endpoint or command.
func parseProvider(data []byte, format, family string) (ip, country string, err error) {
	if format == "trace" {
		ip, country, err = ParseExitTrace(string(data))
	} else {
		var body struct {
			IP          string `json:"ip"`
			Country     string `json:"country"`
			CountryCode string `json:"country_code"`
		}
		if err := json.Unmarshal(data, &body); err != nil {
			return "", "", err
		}
		country = body.Country
		if format == "ipapi" {
			country = body.CountryCode
		}
		ip, country, err = ParseExitTrace("ip=" + body.IP + "\nloc=" + country)
	}
	if err == nil && family != "both" && (net.ParseIP(ip).To4() != nil) != (family == "ipv4") {
		return "", "", errors.New("egress address family mismatch")
	}
	return ip, country, err
}
