package egresscheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

// ProbeTorExit is the original CLI check, shared with Android. The Tor Project
// response is fetched through the selected proxy using certificate-verified
// HTTPS; a local SOCKS listener or foreign country alone does not prove Tor.
func ProbeTorExit(parent context.Context, socks string) error {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	tr := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return smartproxy.DialVia(ctx, socks, "check.torproject.org", "443", 10*time.Second)
		},
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://check.torproject.org/api/ip", nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Transport: tr, Timeout: 14 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}).Do(req)
	if err != nil {
		return fmt.Errorf("Tor status request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Tor status HTTP %d", resp.StatusCode)
	}
	var v struct{ IsTor bool }
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&v); err != nil {
		return err
	}
	if !v.IsTor {
		return errors.New("exit is not verified as Tor by the Tor Project")
	}
	return nil
}
