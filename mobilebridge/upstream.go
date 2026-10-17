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
    IP string
    Region string
}

// A local SOCKS5 proxy is only trusted as a foreign exit after a real
// end-to-end HTTPS response reaches the expected authenticated origin.
// We do not pretend that opening a TCP socket confirms Tor/Psiphon/Aether.
func verifyLocalUpstream(parent context.Context, address string, requireTor bool) (observedExit, error) {
    host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
    if err != nil { return observedExit{}, errors.New("SOCKS address must be host:port") }
    port, err := strconv.Atoi(portText)
    if err != nil || port < 1 || port > 65535 { return observedExit{}, errors.New("invalid SOCKS port") }
    if host != "localhost" {
        ip := net.ParseIP(host)
        if ip == nil || !ip.IsLoopback() { return observedExit{}, errors.New("only a loopback SOCKS server is allowed") }
    }
    if host == "localhost" { host = "127.0.0.1" }
    address = net.JoinHostPort(host, portText)
    proxy, _ := url.Parse("socks5://" + address)
    transport := &http.Transport{
        Proxy: http.ProxyURL(proxy), DisableKeepAlives: true,
        TLSHandshakeTimeout: 5 * time.Second,
        ResponseHeaderTimeout: 5 * time.Second,
    }
    defer transport.CloseIdleConnections()
    client := &http.Client{Transport: transport, Timeout: 10 * time.Second,
        CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
    }
    ctx, cancel := context.WithTimeout(parent, 20*time.Second)
    defer cancel()
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
        "https://www.cloudflare.com/cdn-cgi/trace", nil)
    resp, err := client.Do(req)
    if err != nil { return observedExit{}, err }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK { return observedExit{}, fmt.Errorf("exit trace HTTP %d", resp.StatusCode) }
    raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
    if err != nil { return observedExit{}, err }
    fields := make(map[string]string)
    for _, line := range strings.Split(string(raw), "\n") {
        if k, v, ok := strings.Cut(line, "="); ok { fields[k] = strings.TrimSpace(v) }
    }
    ip := net.ParseIP(fields["ip"])
    region := strings.ToUpper(fields["loc"])
    if ip == nil || ip.IsPrivate() || ip.IsLoopback() || !ip.IsGlobalUnicast() {
        return observedExit{}, errors.New("HTTPS exit response did not contain a public IP")
    }
    if len(region) != 2 || region == "IR" || region == "RU" || region == "XX" {
        return observedExit{}, fmt.Errorf("exit region unverified or disallowed (%q)", region)
    }
    if requireTor {
        req, _ = http.NewRequestWithContext(ctx, http.MethodGet,
            "https://check.torproject.org/api/ip", nil)
        resp, err = client.Do(req)
        if err != nil { return observedExit{}, fmt.Errorf("Tor verification: %w", err) }
        raw, err = io.ReadAll(io.LimitReader(resp.Body, 2048))
        status := resp.StatusCode
        resp.Body.Close()
        if err != nil || status != http.StatusOK {
            return observedExit{}, errors.New("Tor check unavailable")
        }
        var proof struct { IsTor bool `json:"IsTor"`; IP string `json:"IP"` }
        if json.Unmarshal(raw, &proof) != nil || !proof.IsTor || net.ParseIP(proof.IP) == nil {
            return observedExit{}, errors.New("Tor Project did not confirm a Tor exit")
        }
    }
    return observedExit{Address: address, IP: ip.String(), Region: region}, nil
}

// TestCDN is an opt-in bounded fronting assessment on an explicitly supplied
// edge IP. It does not install certificates or assert fronting from HTTP 200.
func TestFront(rawURL, sni, host, edgeIP string) (string, error) {
    if net.ParseIP(strings.TrimSpace(edgeIP)) == nil {
        return "", errors.New("a single numeric edge IP is required")
    }
    plan := edges.Plan{
        URL: rawURL, SNI: sni, Host: host,
        IPs: []string{strings.TrimSpace(edgeIP)}, Rounds: 1,
        Timeout: 7*time.Second, Proof: false,
    }
    report, err := edges.Run(context.Background(), plan, nil)
    if err != nil { return "", err }
    b, err := json.Marshal(report)
    if err != nil { return "", err }
    return string(b), nil
}
