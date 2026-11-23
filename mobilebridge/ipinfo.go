package mobilebridge

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

	"github.com/Nishef1/ktest/internal/egresscheck"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

type ipFamilyResult struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
}

type publicIPReport struct {
	IP        string          `json:"ip"`      // first verified public IP, for older Android clients
	Country   string          `json:"country"`
	Via       string          `json:"via"`     // "direct" or "connection"
	Family    string          `json:"family"`  // requested diagnostic family
	IPv4      *ipFamilyResult `json:"ipv4,omitempty"`
	IPv6      *ipFamilyResult `json:"ipv6,omitempty"`
	IPv4Error string          `json:"ipv4_error,omitempty"`
	IPv6Error string          `json:"ipv6_error,omitempty"`
}

type traceTarget struct {
	host string
	addr string
}

// IPv4 and IPv6 diagnostics use literal destination addresses and TLS
// certificate validation for one.one.one.one. A hostname-only SOCKS request
// would allow the remote proxy to select a different IP family and give a
// misleading "IPv6 working" result. The physical client and proxy can still
// use another address family for the *carrier* itself.
var traceTargetsIPv4 = []traceTarget{
	{"one.one.one.one", "1.1.1.1:443"},
	{"one.one.one.one", "1.0.0.1:443"},
}
var traceTargetsIPv6 = []traceTarget{
	{"one.one.one.one", "[2606:4700:4700::1111]:443"},
	{"one.one.one.one", "[2606:4700:4700::1001]:443"},
}

func validIPFamily(family string) bool {
	return family == "ipv4" || family == "ipv6" || family == "both"
}

// PublicIP retains the earlier one-address contract, explicitly checking IPv4.
// Call PublicIPForFamily to inspect IPv6 or both families independently.
func PublicIP(viaConnection bool) (string, error) {
	return PublicIPForFamily(viaConnection, "ipv4")
}

// PublicIPForFamily measures the observed public IP via an IPv4-only,
// IPv6-only or independent dual-family HTTPS trace. A missing family is NOT
// substituted with another. "both" may return a partial report with the
// unavailable family explained, but returns an error if neither works.
// It is a diagnostic, NOT a setting for the proxy's routing or VPN carrier.
func PublicIPForFamily(viaConnection bool, family string) (string, error) {
	family = strings.ToLower(strings.TrimSpace(family))
	if !validIPFamily(family) {
		return "", errors.New("IP check family must be ipv4, ipv6 or both")
	}
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
	via := "direct"
	if viaConnection {
		via = "connection"
	}
	report := publicIPReport{Via: via, Family: family}
	type result struct {
		family, ip, country string
		err                 error
	}
	families := []string{family}
	if family == "both" {
		families = []string{"ipv4", "ipv6"}
	}
	results := make(chan result, len(families))
	for _, name := range families {
		go func(f string) {
			ip, country, err := checkTraceFamily(ctx, f, socks)
			results <- result{family: f, ip: ip, country: country, err: err}
		}(name)
	}
	for range families {
		r := <-results
		assignTraceResult(&report, r.family, r.ip, r.country, r.err)
	}
	if report.IP == "" {
		return "", fmt.Errorf("%s public IP check failed: IPv4: %s; IPv6: %s",
			family, report.IPv4Error, report.IPv6Error)
	}
	raw, err := json.Marshal(report)
	return string(raw), err
}

func assignTraceResult(report *publicIPReport, family, ip, country string, err error) {
	if err != nil {
		if family == "ipv4" {
			report.IPv4Error = err.Error()
		} else {
			report.IPv6Error = err.Error()
		}
		return
	}
	entry := &ipFamilyResult{IP: ip, Country: country}
	if family == "ipv4" {
		report.IPv4 = entry
	} else {
		report.IPv6 = entry
	}
	// Prefer IPv4 for compatibility with older clients, but preserve IPv6
	// as the primary reported address if it is the only working family.
	if report.IP == "" || family == "ipv4" {
		report.IP, report.Country = ip, country
	}
}

func checkTraceFamily(parent context.Context, family, socks string) (string, string, error) {
	var targets []traceTarget
	if family == "ipv4" {
		targets = traceTargetsIPv4
	} else if family == "ipv6" {
		targets = traceTargetsIPv6
	} else {
		return "", "", errors.New("unsupported IP family")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	type result struct {
		ip, country string
		err         error
	}
	results := make(chan result, len(targets))
	for _, target := range targets {
		go func(t traceTarget) {
			ip, country, err := fetchTrace(ctx, t.host, t.addr, socks, family)
			results <- result{ip: ip, country: country, err: err}
		}(target)
	}
	var lastErr error
	for range targets {
		r := <-results
		if r.err == nil {
			return r.ip, r.country, nil
		}
		lastErr = r.err
	}
	return "", "", fmt.Errorf("%s HTTPS trace unavailable: %w", family, lastErr)
}

func fetchTrace(ctx context.Context, host, addr, socks, family string) (string, string, error) {
	if !validIPFamily(family) || family == "both" {
		return "", "", errors.New("trace must use one IP family")
	}
	destination, _, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(destination) == nil {
		return "", "", errors.New("trace target must be a pinned numeric IP")
	}
	if (net.ParseIP(destination).To4() != nil) != (family == "ipv4") {
		return "", "", errors.New("trace address family mismatch")
	}
	network := "tcp4"
	if family == "ipv6" {
		network = "tcp6"
	}
	tr := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10,
		TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 8 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if socks != "" {
				// Numeric SOCKS destination forces the measured target family;
				// TLS still validates the actual HTTPS hostname, not this IP.
				return smartproxy.DialVia(ctx, socks, destination, "443", 8*time.Second)
			}
			return (&net.Dialer{Timeout: 6 * time.Second}).DialContext(ctx, network, addr)
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
	if err != nil {
		return "", "", err
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || (parsed.To4() != nil) != (family == "ipv4") {
		return "", "", fmt.Errorf("%s probe returned an IP from the wrong address family", family)
	}
	return ip, country, nil
}
