package mobilebridge

import (
	"context"
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
	if activeProxy.routeProfile != nil {
		proxyMu.Unlock()
		return "", errors.New("routes are frozen while connected; disconnect and use the Test button")
	}
	addr := activeProxy.socks.Addr().String()
	proxyMu.Unlock()
	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	results := quickcheck.Run(ctx, port, 9*time.Second)
	check := routeCheck{
		Targets: results,
		Note:    "Only listed HTTPS targets were checked through the SOCKS5 listener. This does not verify a VPN, exit country, or traffic from other apps.",
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
