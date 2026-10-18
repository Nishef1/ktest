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
	"github.com/Nishef1/ktest/internal/connectionsession"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

// The local Go proxy carries TCP, encrypted packet DNS and foreign-exit UDP.
// This is not a system VPN and starting listeners is not proof of Internet access.
type proxySession struct {
	mode         string
	upstream     string
	exitLocation string
	socks        net.Listener
	httpAddress  string
	cancel       context.CancelFunc
	core         *connectionsession.Session
	closeDNS     func()
	diagnostics  *proxyDiagnostics
	native       *nativeCore
	localCores   *localCoreSet
}

type proxyDiagnostics struct {
	mu          sync.Mutex
	dnsFailures int
	dnsError    string
}

type proxyReport struct {
	Running      bool   `json:"running"`
	Mode         string `json:"mode,omitempty"`
	Socks        string `json:"socks,omitempty"`
	HTTP         string `json:"http,omitempty"`
	Coverage     string `json:"coverage"`
	Detail       string `json:"detail"`
	Upstream     string `json:"upstream,omitempty"`
	ExitLocation string `json:"exit_location,omitempty"`
	Phase        string `json:"phase"`
	Error        string `json:"error,omitempty"`
	DNSFailures  int    `json:"dns_failures"`
	DNSError     string `json:"dns_error,omitempty"`
	Native       bool   `json:"native"`
	Method       string `json:"method,omitempty"`
}

type proxyStartup struct {
	mode   string
	phase  string
	cancel context.CancelFunc
}

var proxyMu sync.Mutex
var proxyStartMu sync.Mutex
var proxyGeneration uint64
var activeProxy *proxySession
var pendingProxy *proxyStartup
var proxyFailure string

func currentReportLocked() proxyReport {
	if activeProxy == nil {
		report := proxyReport{Running: false, Phase: "stopped", Coverage: "proxy", Detail: "Stopped", Error: proxyFailure}
		if pendingProxy != nil {
			report.Phase, report.Mode, report.Detail = pendingProxy.phase, pendingProxy.mode, "Preparing connection"
		}
		if proxyFailure != "" {
			report.Phase, report.Detail = "failed", proxyFailure
		}
		return report
	}
	report := proxyReport{
		Running: true, Mode: activeProxy.mode,
		Phase:        "listening",
		Socks:        activeProxy.socks.Addr().String(),
		HTTP:         activeProxy.httpAddress,
		Coverage:     "proxy",
		Upstream:     activeProxy.upstream,
		ExitLocation: activeProxy.exitLocation,
		Detail:       "Local proxy listeners are active. Configure a proxy-capable app; VPN is not enabled.",
	}
	activeProxy.diagnostics.mu.Lock()
	report.DNSFailures, report.DNSError = activeProxy.diagnostics.dnsFailures, activeProxy.diagnostics.dnsError
	activeProxy.diagnostics.mu.Unlock()
	if activeProxy.native != nil {
		report.Native, report.Method = true, activeProxy.native.method
	}
	return report
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
// This low-level entry point uses built-in plain + ClientHello splitting paths.
// Android uses StartAndroidProxy to include its packaged native ByeDPI routes.
func StartProxy(mode string) (string, error) {
	return StartProxyWithUpstream(mode, "")
}

// StartProxyWithUpstream adds a separately started local SOCKS5 transport.
// This adapts the existing CLI -exit-socks route; it does not create another core.
func StartProxyWithUpstream(mode, upstream string) (report string, startErr error) {
	return startProxy(mode, upstream, nil, "")
}

func startProxy(mode, upstream string, native *nativeOptions, localDir string) (report string, startErr error) {
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
	budget := 25 * time.Second
	if native != nil {
		budget = 4 * time.Minute
		if mode == "tor" {
			budget = 7 * time.Minute
		}
	}
	startContext, startCancel := context.WithTimeout(context.Background(), budget)
	startup := &proxyStartup{mode: mode, phase: "preparing", cancel: startCancel}
	pendingProxy, proxyFailure = startup, ""
	proxyMu.Unlock()
	defer func() {
		startCancel()
		proxyMu.Lock()
		defer proxyMu.Unlock()
		if pendingProxy == startup {
			pendingProxy = nil
			if startErr != nil {
				proxyFailure = startErr.Error()
			}
		}
	}()
	switch mode {
	case "balanced", "fast", "aether":
	case "psiphon", "tor":
		if native == nil {
			return "", errors.New("this mode requires its managed Aether backend")
		}
	default:
		return "", fmt.Errorf("mode %q is not available in this Android build", mode)
	}
	var managed *nativeCore
	keepManaged := false
	if native != nil {
		proxyMu.Lock()
		startup.phase = "starting_core"
		proxyMu.Unlock()
		var err error
		managed, err = launchNative(startContext, mode, *native)
		if err != nil {
			return "", err
		}
		cancelNative := context.AfterFunc(startContext, managed.cancel)
		defer func() {
			cancelNative()
			if !keepManaged {
				managed.stop()
			}
		}()
		upstream = managed.address
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
	var localCores *localCoreSet
	keepLocal := false
	if localDir != "" {
		localCores, err = launchAndroidLocalCores(startContext, localDir)
		if err != nil {
			return "", err
		}
		defer func() {
			if !keepLocal {
				localCores.stop()
			}
		}()
		upstreams = append(upstreams, localCores.upstreams...)
	}
	location := ""
	if upstream != "" {
		proxyMu.Lock()
		if pendingProxy == startup {
			startup.phase = "verifying_upstream"
		}
		proxyMu.Unlock()
		var checked observedExit
		var err error
		if managed != nil {
			checked, err = waitNative(startContext, mode, managed)
		} else {
			checked, err = verifyLocalUpstream(startContext, upstream)
		}
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
	diagnostics := &proxyDiagnostics{}
	config.OnEvent = func(e smartproxy.Event) {
		if e.Port == "53" && e.Err != "" {
			diagnostics.mu.Lock()
			diagnostics.dnsFailures++
			diagnostics.dnsError = e.Err
			diagnostics.mu.Unlock()
		}
	}
	connectionpolicy.Configure(mode, &config, rules.Match)
	// Use the same Go trusted/DoH/ECH resolver as the desktop connection.
	// Aether never falls back to Android system DNS.
	config.Resolve, config.Resolve6, err = connectiondns.MobileResolvers(mode, upstream)
	if err != nil {
		return "", err
	}
	exchange, closeDNS, err := connectiondns.MobilePacketDNS(mode, upstream)
	if err != nil {
		return "", err
	}
	config.ExchangeDNS = exchange
	keepDNS := false
	defer func() {
		if !keepDNS {
			closeDNS()
		}
	}()
	if upstream != "" {
		config.VerifyExit = func(ctx context.Context, _ smartproxy.Upstream) error {
			_, err := verifyModeUpstream(ctx, mode, upstream)
			return err
		}
	}
	proxy, err := smartproxy.New(config)
	if err != nil {
		return "", err
	}
	proxyMu.Lock()
	defer proxyMu.Unlock()
	if activeProxy != nil || proxyGeneration != generation {
		return "", errors.New("proxy start canceled or another session became active")
	}
	if err := startContext.Err(); err != nil {
		return "", err
	}
	if managed != nil {
		select {
		case <-managed.done:
			return "", errors.New("native core exited during connection startup")
		default:
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	core, err := connectionsession.Start(ctx, proxy, "127.0.0.1:0")
	if err != nil {
		cancel()
		return "", fmt.Errorf("SOCKS listener: %w", err)
	}
	httpAddress, err := core.StartHTTP("127.0.0.1:0", nil)
	if err != nil {
		cancel()
		core.Stop()
		return "", fmt.Errorf("HTTP listener: %w", err)
	}
	// The session owns the listeners; Android only consumes their addresses.
	session := &proxySession{mode: mode, upstream: upstream, exitLocation: location, socks: core.SOCKS, httpAddress: httpAddress, cancel: cancel, core: core, closeDNS: closeDNS, diagnostics: diagnostics, native: managed, localCores: localCores}
	activeProxy = session
	keepDNS = true
	keepManaged = true
	keepLocal = true
	if localCores != nil {
		for _, child := range localCores.cores {
			go func() {
				select {
				case <-ctx.Done():
				case <-child.done:
					proxy.Remove(child.method)
				}
			}()
		}
	}
	if managed != nil {
		go func() {
			select {
			case <-ctx.Done():
				return
			case <-managed.done:
			}
			proxyMu.Lock()
			stopped := activeProxy == session
			if stopped {
				proxyFailure = "Native core stopped; reconnect to start a new session"
				stopLocked()
			}
			proxyMu.Unlock()
			if stopped {
				StopVpnTun()
			}
		}()
	}
	go func() {
		<-core.Done()
		if ctx.Err() == nil {
			// A failed Go listener also tears down the platform VPN, rather
			// than leaving a TUN pointed at a dead local SOCKS endpoint.
			proxyMu.Lock()
			stopped := activeProxy == session
			if stopped {
				if err := core.Err(); err != nil {
					proxyFailure = err.Error()
				}
				stopLocked()
			}
			proxyMu.Unlock()
			if stopped {
				StopVpnTun()
			}
		}
	}()
	return encodeReport(currentReportLocked()), nil
}

func stopLocked() {
	if activeProxy == nil {
		return
	}
	s := activeProxy
	activeProxy = nil
	s.cancel()
	s.core.Stop()
	s.closeDNS()
	if s.localCores != nil {
		s.localCores.stop()
	}
	if s.native != nil {
		s.native.stop()
	}
}

// CancelProxyStart is non-blocking so Android can cancel a blocking JNI startup
// from its main thread; the worker then calls StopProxy to finish cleanup.
func CancelProxyStart() {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	proxyGeneration++
	if pendingProxy != nil {
		pendingProxy.cancel()
	}
}

// StopProxy terminates listeners and active proxied streams.
func StopProxy() string {
	// Stop packet forwarding BEFORE the SOCKS endpoint disappears.
	// Android still owns the TUN fd and closes it during service teardown.
	StopVpnTun()
	proxyMu.Lock()
	defer proxyMu.Unlock()
	proxyGeneration++
	if pendingProxy != nil {
		pendingProxy.cancel()
		pendingProxy = nil
	}
	proxyFailure = ""
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
