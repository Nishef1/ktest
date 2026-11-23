package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/egresscheck"
)

type ipFamilyResult struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
}

type publicIPReport struct {
	IP        string          `json:"ip"` // first verified public IP, for older Android clients
	Country   string          `json:"country"`
	Via       string          `json:"via"`    // "direct" or "connection"
	Family    string          `json:"family"` // requested diagnostic family
	IPv4      *ipFamilyResult `json:"ipv4,omitempty"`
	IPv6      *ipFamilyResult `json:"ipv6,omitempty"`
	IPv4Error string          `json:"ipv4_error,omitempty"`
	IPv6Error string          `json:"ipv6_error,omitempty"`
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
	return egresscheck.ProbeExitLocationFamily(parent, socks, family)
}
