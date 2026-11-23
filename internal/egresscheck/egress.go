package egresscheck

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
func ProbeForeignExit(parent context.Context, socks string) (ip, country string, err error) {
	ip, country, err = ProbeExitLocation(parent, socks)
	if err != nil {
		return ip, country, err
	}
	return ParseForeignTrace("ip=" + ip + "\nloc=" + country)
}

func ProbeExitLocation(parent context.Context, socks string) (ip, country string, err error) {
	return probeExitTrace(parent, socks, "www.cloudflare.com", "www.cloudflare.com", "")
}

// ProbeExitLocationFamily verifies the actual observed public IP family on a
// numeric destination, independently of the carrier/gateway address family.
func ProbeExitLocationFamily(parent context.Context, socks, family string) (ip, country string, err error) {
	if family == "" || family == "both" {
		return ProbeExitLocation(parent, socks)
	}
	var target string
	switch family {
	case "ipv4":
		target = "1.1.1.1"
	case "ipv6":
		target = "2606:4700:4700::1111"
	default:
		return "", "", errors.New("invalid egress IP family")
	}
	return probeExitTrace(parent, socks, "one.one.one.one", target, family)
}

func ProbeForeignExitFamily(parent context.Context, socks, family string) (ip, country string, err error) {
	ip, country, err = ProbeExitLocationFamily(parent, socks, family)
	if err != nil {
		return ip, country, err
	}
	return ParseForeignTrace("ip=" + ip + "\nloc=" + country)
}

func probeExitTrace(parent context.Context, socks, host, target, family string) (ip, country string, err error) {
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	tr := &http.Transport{
		Proxy:                  nil,
		MaxResponseHeaderBytes: 32 << 10,
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    8 * time.Second,
		ResponseHeaderTimeout:  8 * time.Second,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return smartproxy.DialVia(ctx, socks, target, "443", 8*time.Second)
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 11 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/cdn-cgi/trace", nil)
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
	ip, country, err = ParseExitTrace(string(data))
	if err == nil && family != "" && (net.ParseIP(ip).To4() != nil) != (family == "ipv4") {
		return "", "", errors.New("egress address family mismatch")
	}
	return ip, country, err
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
	if parsed == nil || !parsed.IsGlobalUnicast() || parsed.IsPrivate() {
		return "", "", errors.New("geo-check did not return a public egress IP")
	}
	if len(country) != 2 || country == "XX" || country == "ZZ" || country == "T1" || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
		return ip, country, fmt.Errorf("egress location %q is blocked or unknown under the exit policy", country)
	}
	return ip, country, nil
}
