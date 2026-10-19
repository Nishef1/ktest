package mobilebridge

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/Nishef1/ktest/internal/quickcheck"
)

type routeCheck struct {
	Verified  int                 `json:"verified"`
	Attempted int                 `json:"attempted"`
	Targets   []quickcheck.Result `json:"targets"`
	Note      string              `json:"note"`
}

// CheckRoute tests TLS-verified HTTPS through the actual local SOCKS listener.
// It is a bounded, opt-in active test, not proof of anonymous or VPN-wide routing.
func CheckRoute() (string, error) {
	proxyMu.Lock()
	if activeProxy == nil {
		proxyMu.Unlock()
		return "", errors.New("local proxy is not running")
	}
	addr := activeProxy.socks.Addr().String()
	var probeTLS *tls.Config
	fronting := activeProxy.fronter != nil
	if fronting {
		probeTLS = routeProbeTLS(activeProxy.fronter.Upstream(), activeProxy.frontDir)
	}
	proxyMu.Unlock()
	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 31*time.Second)
	defer cancel()
	results := quickcheck.RunWithTLS(ctx, port, 30*time.Second, probeTLS)
	check := routeCheck{
		Targets: results,
		Note:    "Only listed HTTPS targets were checked through the SOCKS5 listener. This does not verify a VPN, exit country, or traffic from other apps.",
	}
	if fronting {
		check.Note += " This internal check trusts this session's local fronting CA; other Android apps may reject it."
	}
	for _, result := range results {
		if !result.Skipped {
			check.Attempted++
		}
		if result.Success {
			check.Verified++
		}
	}
	b, err := json.Marshal(check)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
