package mobilebridge

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "net"
    "sync"
    "time"

    "github.com/Nishef1/ktest/internal/connectiondns"
    "github.com/Nishef1/ktest/internal/connectionpolicy"
    "github.com/Nishef1/ktest/internal/httpproxy"
    "github.com/Nishef1/ktest/internal/smartproxy"
)

// Only local TCP SOCKS5 + HTTP bridge is supported on Android at present.
// This is not a system VPN and starting listeners is not proof of Internet access.
type proxySession struct {
    mode string
    upstream string
    exitLocation string
    socks net.Listener
    http net.Listener
    cancel context.CancelFunc
}

type proxyReport struct {
    Running bool `json:"running"`
    Mode string `json:"mode,omitempty"`
    Socks string `json:"socks,omitempty"`
    HTTP string `json:"http,omitempty"`
    Coverage string `json:"coverage"`
    Detail string `json:"detail"`
    Upstream string `json:"upstream,omitempty"`
    ExitLocation string `json:"exit_location,omitempty"`
}

var proxyMu sync.Mutex
var proxyStartMu sync.Mutex
var proxyGeneration uint64
var activeProxy *proxySession

func currentReportLocked() proxyReport {
    if activeProxy == nil {
        return proxyReport{Running: false, Coverage: "proxy", Detail: "Stopped"}
    }
    return proxyReport{
        Running: true, Mode: activeProxy.mode,
        Socks: activeProxy.socks.Addr().String(),
        HTTP: activeProxy.http.Addr().String(),
        Coverage: "proxy",
        Upstream: activeProxy.upstream,
        ExitLocation: activeProxy.exitLocation,
        Detail: "Local proxy listeners are active. Configure a proxy-capable app; VPN is not enabled.",
    }
}

func encodeReport(v proxyReport) string {
    b, err := json.Marshal(v)
    if err != nil {
        return "{\"running\":false,\"coverage\":\"proxy\",\"detail\":\"Status unavailable\"}"
    }
    return string(b)
}

// ProxyStatus can be polled by Android without changing the network.
func ProxyStatus() string {
    proxyMu.Lock()
    defer proxyMu.Unlock()
    return encodeReport(currentReportLocked())
}

// StartProxy starts real in-process Go SOCKS5 and HTTP listeners.
// Balanced and fast mirror only the built-in plain + ClientHello splitting
// paths from the desktop CLI. External Xray/Aether/Psiphon/Tor/Windscribe
// processes are deliberately NOT emulated or reported as connected.
func StartProxy(mode string) (string, error) {
    return StartProxyWithUpstream(mode, "")
}

// StartProxyWithUpstream adds a separately started local SOCKS5 transport.
// This adapts the existing CLI -exit-socks route; it does not create another core.
func StartProxyWithUpstream(mode, upstream string) (string, error) {
    // Long upstream validation must never hold proxyMu: Android status polling
    // calls ProxyStatus on the UI thread. Serialize only start calls here.
    proxyStartMu.Lock()
    defer proxyStartMu.Unlock()
    proxyMu.Lock()
    if activeProxy != nil {
        proxyMu.Unlock()
        return "", errors.New("proxy already running; disconnect before switching modes")
    }
    generation := proxyGeneration
    proxyMu.Unlock()
    switch mode {
    case "balanced", "fast", "aether":
    default:
        return "", fmt.Errorf("mode %q is not available in this Android build", mode)
    }
    if mode != "balanced" && mode != "fast" && upstream == "" {
        return "", errors.New("a local SOCKS5 upstream is required for this mode")
    }
    rules, err := smartproxy.NewAIDomainRules("")
    if err != nil {
        return "", err
    }
    var upstreams []smartproxy.Upstream
    if mode == "balanced" || mode == "fast" {
        upstreams = append(smartproxy.PlainUpstreams(), smartproxy.DesyncUpstreams()...)
    }
    location := ""
    if upstream != "" {
        startContext, startCancel := context.WithTimeout(context.Background(), 25*time.Second)
        defer startCancel()
        checked, err := verifyLocalUpstream(startContext, upstream)
        if err != nil {
            return "", fmt.Errorf("upstream not verified: %w", err)
        }
        location = checked.Region
        upstream = checked.Address
        upstreams = append(upstreams, smartproxy.Upstream{
            Name: "Verified " + mode + " SOCKS5", Addr: upstream,
            Exit: true, AIEligible: true, Late: mode == "balanced" || mode == "fast",
            Rank: 9,
        })
    }
    config := smartproxy.Config{Upstreams: upstreams}
    connectionpolicy.Configure(mode, &config, rules.Match)
    // Use the same Go trusted/DoH/ECH resolver as the desktop connection.
    // Aether never falls back to Android system DNS.
    config.Resolve, config.Resolve6, err = connectiondns.MobileResolvers(mode, upstream)
    if err != nil { return "", err }
    if upstream != "" {
        config.VerifyExit = func(ctx context.Context, _ smartproxy.Upstream) error {
            _, err := verifyLocalUpstream(ctx, upstream)
            return err
        }
    }
    proxy, err := smartproxy.New(config)
    if err != nil { return "", err }
    proxyMu.Lock()
    defer proxyMu.Unlock()
    if activeProxy != nil || proxyGeneration != generation {
        return "", errors.New("proxy start canceled or another session became active")
    }
    socksListener, err := net.Listen("tcp4", "127.0.0.1:0")
    if err != nil {
        return "", fmt.Errorf("SOCKS listener: %w", err)
    }
    httpListener, err := net.Listen("tcp4", "127.0.0.1:0")
    if err != nil {
        _ = socksListener.Close()
        return "", fmt.Errorf("HTTP listener: %w", err)
    }
    ctx, cancel := context.WithCancel(context.Background())
    session := &proxySession{mode: mode, upstream: upstream, exitLocation: location, socks: socksListener, http: httpListener, cancel: cancel}
    activeProxy = session
    bridge := &httpproxy.Server{Upstream: socksListener.Addr().String()}
    run := func(name string, serve func() error) {
        err := serve()
        if ctx.Err() == nil {
            // A failed Go listener also tears down the platform VPN, rather
            // than leaving a TUN pointed at a dead local SOCKS endpoint.
            _ = name
            _ = err
            proxyMu.Lock()
            stopped := activeProxy == session
            if stopped {
                stopLocked()
            }
            proxyMu.Unlock()
            if stopped {
                StopVpnTun()
            }
        }
    }
    go run("socks", func() error { return proxy.Serve(ctx, socksListener) })
    go run("http", func() error { return bridge.Serve(ctx, httpListener) })
    return encodeReport(currentReportLocked()), nil
}

func stopLocked() {
    if activeProxy == nil {
        return
    }
    s := activeProxy
    activeProxy = nil
    s.cancel()
    _ = s.socks.Close()
    _ = s.http.Close()
}

// StopProxy terminates listeners and active proxied streams.
func StopProxy() string {
    // Stop packet forwarding BEFORE the SOCKS endpoint disappears.
    // Android still owns the TUN fd and closes it during service teardown.
    StopVpnTun()
    proxyMu.Lock()
    defer proxyMu.Unlock()
    proxyGeneration++
    stopLocked()
    return encodeReport(currentReportLocked())
}

// ProxyReady performs a bounded local handshake; it tests only listener readiness.
func ProxyReady() bool {
    proxyMu.Lock()
    if activeProxy == nil {
        proxyMu.Unlock()
        return false
    }
    addr := activeProxy.socks.Addr().String()
    proxyMu.Unlock()
    conn, err := net.DialTimeout("tcp4", addr, 800*time.Millisecond)
    if err != nil {
        return false
    }
    _ = conn.Close()
    return true
}
