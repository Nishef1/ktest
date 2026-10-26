package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/cdnranges"
	"github.com/Nishef1/ktest/internal/connectiondns"
	"github.com/Nishef1/ktest/internal/connectionpolicy"
	"github.com/Nishef1/ktest/internal/connectionsession"
	"github.com/Nishef1/ktest/internal/egresscheck"
	"github.com/Nishef1/ktest/internal/front"
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
	carrier      *fastCarrier
	localCores   *localCoreSet
	xrayError    string
	fronter      *front.Fronter
	frontDir     string
	automatic    *automaticExit
}

type proxyDiagnostics struct {
	mu              sync.Mutex
	dnsFailures     int
	dnsError        string
	tcpAttempts     int
	tcpFailures     int
	tcpBlocked      int // refused by the mode's policy, not the network
	tlsResponses    int
	udpAssociations int
	udpFailures     int
	udp443Failures  int
	lastPath        string // method label only; no destination, credentials, or payloads
	lastRouteMS     int64
	lastConnectMS   int64
	lastFailure     string // classified filtering kind only, e.g. "SNI reset"
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
	// AIExit: a verified non-Iran exit exists, so AI/TikTok can connect.
	// An Iran-located WARP still carries ordinary sites in Aether.
	AIExit          bool   `json:"ai_exit"`
	Phase           string `json:"phase"`
	Error           string `json:"error,omitempty"`
	DNSFailures     int    `json:"dns_failures"`
	DNSError        string `json:"dns_error,omitempty"`
	TCPAttempts     int    `json:"tcp_attempts"`
	TCPFailures     int    `json:"tcp_failures"`
	TCPBlocked      int    `json:"tcp_blocked"`
	TLSResponses    int    `json:"tls_responses"`
	UDPAssociations int    `json:"udp_associations"`
	UDPFailures     int    `json:"udp_failures"`
	UDP443Failures  int    `json:"udp_443_failures"`
	LastRoute       string `json:"last_route,omitempty"`
	LastRouteMS     int64  `json:"last_route_ms"`
	LastConnectMS   int64  `json:"last_connect_ms"`
	Native          bool   `json:"native"`
	Method          string `json:"method,omitempty"`
	Fronting        bool   `json:"fronting"`
	FrontAccepted   int    `json:"front_accepted,omitempty"`
	FrontRefused    int    `json:"front_refused,omitempty"`
	FrontDisabled   string `json:"front_disabled,omitempty"`
	XrayReady       bool   `json:"xray_ready"`
	XrayError       string `json:"xray_error,omitempty"`
	// Filtering is the network-level summary of failure kinds and the method
	// families that beat them; LastFailure the latest classified kind.
	Filtering   string `json:"filtering,omitempty"`
	LastFailure string `json:"last_failure,omitempty"`
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
	report.TCPAttempts, report.TCPFailures, report.TLSResponses = activeProxy.diagnostics.tcpAttempts, activeProxy.diagnostics.tcpFailures, activeProxy.diagnostics.tlsResponses
	report.TCPBlocked = activeProxy.diagnostics.tcpBlocked
	report.UDPAssociations, report.UDPFailures, report.UDP443Failures = activeProxy.diagnostics.udpAssociations, activeProxy.diagnostics.udpFailures, activeProxy.diagnostics.udp443Failures
	report.LastRoute, report.LastRouteMS, report.LastConnectMS = activeProxy.diagnostics.lastPath, activeProxy.diagnostics.lastRouteMS, activeProxy.diagnostics.lastConnectMS
	report.LastFailure = activeProxy.diagnostics.lastFailure
	activeProxy.diagnostics.mu.Unlock()
	if activeProxy.core != nil && activeProxy.core.Proxy != nil {
		report.Filtering = activeProxy.core.Proxy.FilteringSummary()
		report.AIExit = activeProxy.core.Proxy.HasVerifiedExit()
	}
	if activeProxy.native != nil {
		report.Native, report.Method = true, activeProxy.native.method
	}
	if activeProxy.automatic != nil {
		if address, method, location := activeProxy.automatic.snapshot(); address != "" {
			report.Upstream, report.Method, report.ExitLocation, report.Native = address, method, location, true
		}
	}
	report.XrayError = activeProxy.xrayError
	if activeProxy.localCores != nil {
		for _, c := range activeProxy.localCores.cores {
			if c.method != "Xray TLS fragment" {
				continue
			}
			select {
			case <-c.done:
				report.XrayError = "Xray local core exited; other strategies remain available"
			default:
				report.XrayReady = true
			}
		}
	}
	if activeProxy.fronter != nil {
		report.Fronting = true
		report.FrontAccepted, report.FrontRefused = activeProxy.fronter.Stats()
		report.FrontDisabled = activeProxy.fronter.Disabled()
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
	return startProxyWithFronting(mode, upstream, native, localDir, "")
}

func startProxyWithFronting(mode, upstream string, native *nativeOptions, localDir, frontDir string) (report string, startErr error) {
	return startProxyWithNativeCores(mode, upstream, native, localDir, frontDir, "")
}

// localStateDir is explicitly the Android filesDir, not the APK native
// directory. Xray writes only temporary non-secret config there.
func startProxyWithNativeCores(mode, upstream string, native *nativeOptions, localDir, frontDir, localStateDir string) (report string, startErr error) {
	return startProxyConfigured(context.Background(), mode, upstream, native, localDir, frontDir, localStateDir, false)
}

func startProxyConfigured(parent context.Context, mode, upstream string, native *nativeOptions, localDir, frontDir, localStateDir string, testOnly bool) (report string, startErr error) {
	if mode == "fast" && upstream != "" {
		return "", errors.New("Fast only permits managed Aether exits; use Balanced for an external SOCKS core")
	}
	// Long upstream validation must never hold proxyMu: Android status polling
	// calls ProxyStatus on the UI thread. Serialize only start calls here.
	proxyStartMu.Lock()
	defer proxyStartMu.Unlock()
	if localStateDir != "" && (mode == "balanced" || mode == "fast") {
		scanMu.Lock()
		scanning := scanState.Running
		scanMu.Unlock()
		if scanning {
			return "", errors.New("stop the CDN scan before testing or connecting")
		}
	}
	if !testOnly {
		routeTestMu.Lock()
		manualTest := routeTestState.Running && routeTestState.Manual
		routeTestMu.Unlock()
		if manualTest {
			return "", errors.New("finish or cancel the manual route test before connecting")
		}
	}
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
	startContext, startCancel := context.WithTimeout(parent, budget)
	if testOnly {
		startCancel()
		startContext, startCancel = context.WithTimeout(parent, 3*time.Minute)
	}
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
	if localStateDir != "" && realPrivateDirectory(localStateDir) {
		cdnranges.Load(localStateDir)
	}
	// Bounded preflight, not an exhaustive scan: keep measured edges for this
	// network, then allow live routing to adapt to actual target responses.
	if !testOnly {
		probeDir := localStateDir
		if probeDir == "" && native != nil {
			probeDir = native.privateDir
		}
		autoPrepareNetworkEdges(startContext, probeDir, mode)
	}
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
	var verifiedNative *observedExit
	var carrier *fastCarrier
	keepCarrier := false
	keepManaged := false
	if native != nil {
		proxyMu.Lock()
		startup.phase = "starting_core"
		proxyMu.Unlock()
		var err error
		if native.viaFast {
			if mode != "aether" && mode != "tor" && mode != "psiphon" {
				return "", errors.New("only Aether, Psiphon and Tor can run through Fast")
			}
			carrier, err = startFastCarrier(startContext, native.libraryDir, native.privateDir)
			if err != nil {
				// This is an optional first-hop helper, not the chosen exit.
				// Failure to start Fast must never prevent direct Aether,
				// Psiphon CDN or Tor from being tried independently.
				carrier, native.carrier, native.viaFast = nil, "", false
			} else {
				defer func() {
					if !keepCarrier {
						carrier.stop()
					}
				}()
				native.carrier = carrier.address
			}
		}
		if mode == "aether" && native.profile == nil {
			var verified observedExit
			managed, verified, err = launchVerifiedNativeProfiles(startContext, *native)
			if err == nil {
				verifiedNative = &verified
			}
		} else if mode == "psiphon" && native.profile == nil {
			// The old path launched only one profile, ignoring the WARP-first
			// switch and never reaching standalone/CDN fallback methods.
			var verified observedExit
			managed, verified, err = launchPsiphonTorLadder(startContext, mode, *native)
			if err == nil {
				verifiedNative = &verified
			}
		} else {
			managed, err = launchNative(startContext, mode, *native)
		}
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
	var upstreams []smartproxy.Upstream
	if mode == "balanced" || mode == "fast" {
		upstreams = append(smartproxy.PlainUpstreams(), smartproxy.DesyncUpstreams()...)
	}
	var err error
	var localCores *localCoreSet
	var xrayError string
	keepLocal := false
	if localDir != "" {
		localCores, err = launchAndroidLocalCores(startContext, localDir, testOnly)
		if err != nil {
			return "", err
		}
		defer func() {
			if !keepLocal {
				localCores.stop()
			}
		}()
		if localStateDir != "" && androidXrayEnabled(mode) {
			// Xray is an optional local route in both Balanced and Fast.
			// A failed Xray start never removes the verified ByeDPI fallbacks.
			if err := attachAndroidXray(startContext, localCores, localDir, localStateDir); err != nil {
				xrayError = err.Error()
			}
		}
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
		if verifiedNative != nil {
			checked = *verifiedNative
		} else if managed != nil {
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
			Exit: true, AIEligible: foreignRegion(checked), Late: mode == "balanced" || mode == "fast",
			Rank: 9,
		})
	}
	config := smartproxy.Config{Upstreams: upstreams, RecoverIPHostSNI: localDir != ""}
	var automatic *automaticExit
	keepAutomatic := false
	if !testOnly && (mode == "balanced" || mode == "fast") {
		config.HistoryFile, config.HistoryKey = mobileHistory(mode, localStateDir)
		if localDir != "" && localStateDir != "" && upstream == "" {
			automatic = newAutomaticExit(mode, localDir, localStateDir, config.HistoryKey)
			defer func() {
				if !keepAutomatic {
					automatic.stop()
				}
			}()
			config.EnsureExit = automatic.ensure
			config.VerifyExit = func(ctx context.Context, u smartproxy.Upstream) error {
				_, err := verifyLocalUpstream(ctx, u.Addr)
				return err
			}
		}
	}
	diagnostics := &proxyDiagnostics{}
	config.OnEvent = func(e smartproxy.Event) {
		if e.Probe {
			return
		}
		diagnostics.mu.Lock()
		defer diagnostics.mu.Unlock()
		if e.Port == "53" && e.Err != "" {
			diagnostics.dnsFailures++
			diagnostics.dnsError = "DNS exchange failed"
		}
		if e.UDP {
			if e.OK {
				diagnostics.udpAssociations++
			} else if e.Err != "" {
				diagnostics.udpFailures++
				if e.Port == "443" {
					diagnostics.udp443Failures++
				}
			}
			return
		}
		if e.Port != "53" {
			diagnostics.tcpAttempts++
			switch {
			case e.Blocked:
				diagnostics.tcpBlocked++
			case e.Err != "":
				diagnostics.tcpFailures++
			}
			if e.Failure != "" {
				diagnostics.lastFailure = e.Failure
			}
			if e.TLSResponse {
				diagnostics.tlsResponses++
			}
			if e.OK && e.Path != "" {
				diagnostics.lastPath = e.Path
				diagnostics.lastRouteMS = e.Took.Milliseconds()
				diagnostics.lastConnectMS = e.ConnectMS
			}
		}
	}
	connectionpolicy.Configure(mode, &config)
	// Use the same Go trusted/DoH/ECH resolver as the desktop connection.
	// Aether never falls back to Android system DNS.
	customDNS := currentDNSOverride()
	config.Resolve, config.Resolve6, err = connectiondns.MobileResolversWithCustom(mode, upstream, customDNS)
	if err != nil {
		return "", err
	}
	exchange, closeDNS, err := connectiondns.MobilePacketDNSWithCustom(mode, upstream, customDNS)
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
	var fronter *front.Fronter
	if frontDir != "" {
		if mode != "balanced" && mode != "fast" {
			return "", errors.New("local CA fronting is only offered for Balanced and Fast")
		}
		ca, err := loadAndroidFrontCA(frontDir)
		if err != nil {
			return "", fmt.Errorf("Android CA cannot enable fronting: %w", err)
		}
		// The same desktop domain-family matcher, hedged front scoring,
		// TLS upstream verification and reject-after-app-CA-failure are reused.
		// A public HTTPS status is not proof of reachability for other services.
		preferred := map[string][]string{}
		if localStateDir != "" {
			for _, provider := range []string{"cloudflare", "google", "fastly", "meta"} {
				preferred[provider] = loadVerifiedCDNEdges(localStateDir, provider)
			}
		}
		fronter = front.New(front.Config{CA: ca, Families: front.DefaultFamilies(), Resolve: config.Resolve, PreferredEdges: preferred})
		if localStateDir != "" {
			targets, targetErr := loadRouteTargets(localStateDir)
			if targetErr != nil {
				return "", targetErr
			}
			// Explicit diagnostics test individual strategies. Both connection modes
			// retain in-family hedging and exact-host fronting consent.
			candidates := fronter.Upstreams()
			if !testOnly {
				candidates = []smartproxy.Upstream{fronter.Upstream()}
			}
			for _, candidate := range candidates {
				u := candidate
				originalMatch := u.Match
				u.Match = func(host string) bool {
					return routeFrontingAllowed(targets, host) && (originalMatch == nil || originalMatch(host))
				}
				config.Upstreams = append(config.Upstreams, u)
			}
		} else {
			config.Upstreams = append(config.Upstreams, fronter.Upstream())
		}
	}
	if upstream != "" {
		// VerifyExit guards AI destinations and stays foreign-only; the
		// carrier check serves ordinary sites in Aether (ExitRequired).
		config.VerifyExit = func(ctx context.Context, _ smartproxy.Upstream) error {
			checked, err := verifyLocalUpstream(ctx, upstream)
			if err == nil && mode == "tor" {
				err = egresscheck.ProbeTorExit(ctx, checked.Address)
			}
			return err
		}
		config.VerifyCarrier = func(ctx context.Context, _ smartproxy.Upstream) error {
			_, err := verifyModeUpstream(ctx, mode, upstream)
			return err
		}
	}
	if testOnly {
		if _, err := runRouteDiagnostics(startContext, &config, localStateDir); err != nil {
			return "", err
		}
		return "{}", nil
	}
	if !testOnly && (mode == "balanced" || mode == "fast") && localStateDir != "" {
		// The latest tests on this network give each tested site its best
		// method as the first choice; live learning still decides.
		if targets, targetErr := loadRouteTargets(localStateDir); targetErr == nil {
			names := map[string]bool{}
			for _, u := range config.Upstreams {
				names[u.Name] = true
			}
			config.Seeds, config.SeedDefault = routeSeeds(localStateDir, targets, names)
		}
	}
	proxy, err := smartproxy.New(config)
	if err != nil {
		return "", err
	}
	if automatic != nil {
		automatic.proxy = proxy
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
	androidSession := !testOnly && (localStateDir != "" || (native != nil && native.privateDir != ""))
	socksBind, httpBind := localProxyAddresses(androidSession)
	core, err := connectionsession.Start(ctx, proxy, socksBind)
	if err != nil {
		cancel()
		return "", listenerError("SOCKS5", socksBind, err)
	}
	httpAddress, err := core.StartHTTP(httpBind, nil)
	if err != nil {
		cancel()
		core.Stop()
		return "", listenerError("HTTP", httpBind, err)
	}
	// The session owns the listeners; Android only consumes their addresses.
	session := &proxySession{mode: mode, upstream: upstream, exitLocation: location, socks: core.SOCKS, httpAddress: httpAddress, cancel: cancel, core: core, closeDNS: closeDNS, diagnostics: diagnostics, native: managed, carrier: carrier, localCores: localCores, fronter: fronter, xrayError: xrayError, automatic: automatic}
	activeProxy = session
	session.frontDir = frontDir
	if !testOnly && localStateDir != "" {
		refreshRangesInBackground(ctx, localStateDir, core.SOCKS.Addr().String())
	}
	if automatic != nil && shouldWarmAutomaticExit(mode) {
		// Warm the foreign exit up now, in parallel with local routes, so the
		// first protected site does not wait for its bootstrap in Balanced.
		go func() { _ = automatic.ensure(ctx) }()
	}
	keepDNS = true
	keepManaged = true
	keepLocal = true
	keepCarrier = true
	keepAutomatic = true
	if localCores != nil {
		for _, child := range localCores.cores {
			go func() {
				select {
				case <-ctx.Done():
				case <-child.done:
					// Future connections race the remaining methods.
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
	if s.automatic != nil {
		s.automatic.stop()
	}
	s.closeDNS()
	if s.localCores != nil {
		s.localCores.stop()
	}
	if s.native != nil {
		s.native.stop()
	}
	if s.carrier != nil {
		s.carrier.stop()
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
