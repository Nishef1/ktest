package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/edges"
)

type observedExit struct {
	Address string
	IP      string
	Region  string
}

// verifyLocalUpstream checks the existing CLI -exit-socks route through a
// bounded, certificate-validated HTTPS request. It does not start a second
// Tor/Psiphon/Aether transport or authenticate the name of the external core.
func verifyLocalUpstream(parent context.Context, address string) (observedExit, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return observedExit{}, errors.New("SOCKS address must be host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return observedExit{}, errors.New("invalid SOCKS port")
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return observedExit{}, errors.New("only a loopback SOCKS server is allowed")
	}
	address = net.JoinHostPort(host, portText)
	proxyURL, err := url.Parse("socks5://" + address)
	if err != nil {
		return observedExit{}, err
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyURL(proxyURL),
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return observedExit{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return observedExit{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return observedExit{}, fmt.Errorf("exit trace HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return observedExit{}, err
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			fields[k] = strings.TrimSpace(v)
		}
	}
	outIP := net.ParseIP(fields["ip"])
	region := strings.ToUpper(fields["loc"])
	if outIP == nil || outIP.IsPrivate() || outIP.IsLoopback() || !outIP.IsGlobalUnicast() {
		return observedExit{}, errors.New("HTTPS exit response lacked a public IP")
	}
	if len(region) != 2 || region == "IR" || region == "RU" || region == "XX" {
		return observedExit{}, fmt.Errorf("exit region unverified or disallowed (%q)", region)
	}
	return observedExit{Address: address, IP: outIP.String(), Region: region}, nil
}

// TestFront calls the existing Go edges diagnostic. It does not create a
// second CDN-fronting transport or assert that a TLS handshake proves routing.
func TestFront(rawURL, sni, host, edgeIP string) (string, error) {
	edgeIP = strings.TrimSpace(edgeIP)
	if net.ParseIP(edgeIP) == nil {
		return "", errors.New("a single numeric edge IP is required")
	}
	plan := edges.Plan{
		URL: rawURL, SNI: sni, Host: host,
		IPs: []string{edgeIP}, Rounds: 1,
		Timeout: 7 * time.Second, Proof: false,
	}
	report, err := edges.Run(context.Background(), plan, nil)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
