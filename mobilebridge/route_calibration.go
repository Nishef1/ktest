package mobilebridge

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nishef1/ktest/internal/connectionsession"
	"github.com/Nishef1/ktest/internal/quickcheck"
	"github.com/Nishef1/ktest/internal/routeplan"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

type routeTestReport struct {
	Running       bool               `json:"running"`
	Manual        bool               `json:"manual"`
	Canceled      bool               `json:"canceled"`
	Reused        bool               `json:"reused"`
	Completed     int                `json:"completed"`
	Total         int                `json:"total"`
	Phase         string             `json:"phase"`
	CurrentTarget string             `json:"current_target"`
	CurrentMethod string             `json:"current_method"`
	ElapsedMS     int64              `json:"elapsed_ms"`
	Fresh         bool               `json:"fresh"`
	Error         string             `json:"error,omitempty"`
	Note          string             `json:"note"`
	Profile       *routeplan.Profile `json:"profile,omitempty"`
	started       time.Time
	privateDir    string
}

var routeTestMu sync.Mutex
var routeTestState routeTestReport
var routeTestCancel context.CancelFunc

// The Android caller sets an ephemeral OS network handle before a manual
// test or Balanced connection. This is not an SSID, BSSID, operator ID or
// device identifier. It is hashed into the private route-profile cache key.
var routeNetworkMu sync.Mutex
var routeNetworkToken string

func SetRouteNetworkToken(token string) error {
	if len(token) == 0 || len(token) > 96 || strings.IndexFunc(token, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		return errors.New("active Android network identity is unavailable")
	}
	routeNetworkMu.Lock()
	routeNetworkToken = token
	routeNetworkMu.Unlock()
	return nil
}

func currentRouteNetworkToken() string {
	routeNetworkMu.Lock()
	defer routeNetworkMu.Unlock()
	return routeNetworkToken
}

func routeWorkActive() bool {
	proxyMu.Lock()
	active := activeProxy != nil || pendingProxy != nil
	proxyMu.Unlock()
	routeTestMu.Lock()
	active = active || routeTestState.Running
	routeTestMu.Unlock()
	return active
}

// StartRouteTest is an explicit offline action. It starts the existing cores,
// measures isolated routes, saves one profile and tears the test cores down.
// It never establishes a TUN, starts a connected session or changes a live one.
func StartRouteTest(mode, upstream, nativeDir, privateDir string, fronting bool) error {
	if !proxyStartMu.TryLock() {
		return errors.New("disconnect or finish the current startup before testing routes")
	}
	defer proxyStartMu.Unlock()
	if mode != "balanced" {
		return errors.New("route calibration is available only in Balanced; Fast remains adaptive")
	}
	if routeWorkActive() {
		return errors.New("disconnect before testing routes")
	}
	dir, err := realRouteDirectory(privateDir)
	if err != nil {
		return err
	}
	privateDir = dir
	routeTestMu.Lock()
	if routeTestState.Running {
		routeTestMu.Unlock()
		return errors.New("route test is already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	routeTestState = routeTestReport{Running: true, Manual: true, Phase: "preparing", started: time.Now(), privateDir: dir}
	routeTestCancel = cancel
	routeTestMu.Unlock()
	go func() {
		defer cancel()
		frontDir := ""
		if fronting {
			frontDir = privateDir
		}
		_, err := startProxyConfigured(ctx, mode, upstream, nil, nativeDir, frontDir, privateDir, true)
		routeTestMu.Lock()
		defer routeTestMu.Unlock()
		routeTestState.Running = false
		routeTestState.ElapsedMS = time.Since(routeTestState.started).Milliseconds()
		if err != nil && !routeTestState.Canceled {
			routeTestState.Error = err.Error()
			routeTestState.Phase = "failed"
		}
		routeTestCancel = nil
	}()
	return nil
}

func CancelRouteTest() {
	routeTestMu.Lock()
	defer routeTestMu.Unlock()
	if routeTestCancel != nil {
		routeTestState.Canceled = true
		routeTestCancel()
	}
}

// RouteTestStatus only reads private observations; polling never causes traffic.
func RouteTestStatus(privateDir, mode string) (string, error) {
	if mode != "balanced" {
		return "{}", nil
	}
	dir, err := realRouteDirectory(privateDir)
	if err != nil {
		return "", err
	}
	routeTestMu.Lock()
	state := routeTestState
	if state.privateDir != dir {
		state = routeTestReport{}
	}
	if state.Running && !state.started.IsZero() {
		state.ElapsedMS = time.Since(state.started).Milliseconds()
	}
	routeTestMu.Unlock()
	if !state.Running {
		state.Profile, state.Fresh = nil, false
		if cached, err := routeplan.Load(dir); err == nil {
			state.Profile = cached
			state.Fresh = cached.Fresh(time.Now())
		} else if !errors.Is(err, os.ErrNotExist) && state.Error == "" {
			state.Error = err.Error()
		}
	}
	state.Note = "Preconnection observations only. The route stays fixed while connected; no automatic retest or fallback. HTTP refusals and native-app CA trust are separate from opening a site."
	raw, err := json.Marshal(state)
	return string(raw), err
}

func routeProfileKey(targets []routeTarget, config smartproxy.Config, privateDir string) string {
	parts := []string{routeTargetsRevision(targets), "stable-routing-v3", currentRouteNetworkToken()}
	for _, u := range config.Upstreams {
		parts = append(parts, u.Name)
		if u.Exit {
			// Native loopback ports change on every launch, but an explicitly
			// supplied foreign exit is part of the tested route identity.
			parts = append(parts, u.Addr)
		}
		if u.Takeover != nil {
			if cert := routeTargetsPublicCA(privateDir); cert != nil {
				sum := sha256.Sum256(cert.Raw)
				parts = append(parts, hex.EncodeToString(sum[:]))
			}
		}
	}
	raw, _ := json.Marshal(parts)
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func prepareFrozenRoutes(ctx context.Context, config *smartproxy.Config, privateDir string, manual bool) (profile *routeplan.Profile, err error) {
	targets, err := loadRouteTargets(privateDir)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, errors.New("add at least one target before testing or connecting")
	}
	started := time.Now()
	routeTestMu.Lock()
	canceled := manual && routeTestState.Canceled
	if manual && routeTestState.privateDir == privateDir && !routeTestState.started.IsZero() {
		started = routeTestState.started
	}
	routeTestState = routeTestReport{Running: true, Manual: manual, Canceled: canceled, Phase: "loading", started: started, privateDir: privateDir}
	routeTestMu.Unlock()
	defer func() {
		routeTestMu.Lock()
		defer routeTestMu.Unlock()
		routeTestState.Running = false
		routeTestState.ElapsedMS = time.Since(started).Milliseconds()
		if errors.Is(err, context.Canceled) {
			routeTestState.Canceled, routeTestState.Phase = true, "canceled"
		} else if err != nil {
			routeTestState.Error = err.Error()
			routeTestState.Phase = "failed"
		}
	}()
	byMethod := map[string]smartproxy.Upstream{}
	var methods []routeplan.Method
	for _, upstream := range config.Upstreams {
		u := upstream
		byMethod[u.Name] = u
		methods = append(methods, routeplan.Method{Name: u.Name, General: u.Match == nil && u.Takeover == nil && !u.Exit,
			Eligible: func(target routeplan.Target) bool {
				parsed, parseErr := url.Parse(target.URL)
				if parseErr != nil {
					return false
				}
				host := parsed.Hostname()
				if u.Takeover != nil && parsed.Port() != "" && parsed.Port() != "443" {
					return false
				}
				if u.Match != nil && !u.Match(host) {
					return false
				}
				return config.ExitOnly == nil || !config.ExitOnly(host) || (u.Exit && u.AIEligible)
			},
		})
	}
	var planTargets []routeplan.Target
	for _, target := range targets {
		planTargets = append(planTargets, routeplan.Target{ID: target.ID, Name: target.Name, URL: target.URL})
	}
	key := routeProfileKey(targets, *config, privateDir)
	// Older builds did not record the target revision independently. Migrate
	// only if every saved exact ID/URL still equals the current user target list;
	// otherwise keep the explicit-manual-test protection for target edits.
	force := manual
	if !manual {
		if old, loadErr := routeplan.Load(privateDir); loadErr == nil && old.Fresh(time.Now()) &&
			old.TargetsKey != key && legacyProfileMatchesTargets(old, targets) {
			force = true
		}
	}
	profile, reused, err := routeplan.LoadOrTestWithRevision(ctx, privateDir, key, routeTargetsRevision(targets), force, time.Now(), func() (*routeplan.Profile, error) {
		return routeplan.CalibrateWithWorkers(ctx, planTargets, methods, func(ctx context.Context, target routeplan.Target, method routeplan.Method) routeplan.Sample {
			return measureMethod(ctx, *config, byMethod[method.Name], target, privateDir)
		}, func(progress routeplan.Progress) {
			routeTestMu.Lock()
			routeTestState.Completed, routeTestState.Total = progress.Completed, progress.Total
			routeTestState.CurrentTarget, routeTestState.CurrentMethod = progress.Target, progress.Method
			routeTestState.Phase = progress.Phase
			routeTestMu.Unlock()
		}, 4)
	})
	if err != nil {
		return nil, err
	}
	if !profile.Usable() {
		return nil, errors.New("no target or generic route returned repeated verified HTTPS; inspect results and retry")
	}
	pins := &smartproxy.FrozenRoutes{Default: profile.Default, Targets: map[string]string{}}
	for _, u := range config.Upstreams {
		if u.Exit && u.AIEligible {
			pins.Protected = u.Name
			break
		}
	}
	for _, selection := range profile.Selections {
		u, parseErr := url.Parse(selection.URL)
		if parseErr != nil {
			continue
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		key := net.JoinHostPort(strings.ToLower(u.Hostname()), port)
		// Multiple paths on one host share one stable transport. Prefer a
		// content-verified route over a transport-only response/refusal.
		if selection.Method == "" || selection.Assessment != "https_verified" {
			// Root-page HTTP refusals are not evidence that native APIs or
			// media are broken. Try the independently verified generic route
			// instead of pinning this entire hostname to an empty route.
			continue
		}
		pins.Targets[key] = selection.Method
	}
	for _, method := range append([]string{pins.Default, pins.Protected}, mapValues(pins.Targets)...) {
		if method != "" {
			if _, present := byMethod[method]; !present {
				return nil, errors.New("a cached method is unavailable; run Test manually before connecting")
			}
		}
	}
	config.Frozen = pins
	routeTestMu.Lock()
	routeTestState.Profile, routeTestState.Reused, routeTestState.Fresh = profile, reused, profile.Fresh(time.Now())
	routeTestState.Phase = "complete"
	routeTestMu.Unlock()
	return profile, nil
}

func legacyProfileMatchesTargets(p *routeplan.Profile, targets []routeTarget) bool {
	if p == nil || p.TargetsRevision != "" || len(p.Selections) != len(targets) {
		return false
	}
	remaining := make(map[string]string, len(targets))
	for _, target := range targets {
		remaining[target.ID] = target.URL
	}
	for _, selection := range p.Selections {
		url, ok := remaining[selection.TargetID]
		if !ok || url != selection.URL {
			return false
		}
		delete(remaining, selection.TargetID)
	}
	return len(remaining) == 0
}

func mapValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func measureMethod(parent context.Context, base smartproxy.Config, upstream smartproxy.Upstream, target routeplan.Target, privateDir string) routeplan.Sample {
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()
	var tcpMS, tlsMS atomic.Int64
	base.Upstreams, base.Frozen = []smartproxy.Upstream{upstream}, nil
	base.OnEvent = func(e smartproxy.Event) {
		if e.TLSResponse {
			tcpMS.Store(e.ConnectMS)
		}
	}
	proxy, err := smartproxy.New(base)
	if err != nil {
		return routeplan.Sample{Error: err.Error()}
	}
	core, err := connectionsession.Start(ctx, proxy, "127.0.0.1:0")
	if err != nil {
		return routeplan.Sample{Error: err.Error()}
	}
	defer core.Stop()
	proxyURL, _ := url.Parse("socks5://" + core.SOCKS.Addr().String())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: routeProbeTLS(upstream, privateDir), DisableKeepAlives: true, ForceAttemptHTTP2: true, MaxResponseHeaderBytes: 32 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var tlsStarted time.Time
	trace := &httptrace.ClientTrace{TLSHandshakeStart: func() { tlsStarted = time.Now() }, TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
		if !tlsStarted.IsZero() {
			tlsMS.Store(time.Since(tlsStarted).Milliseconds())
		}
	}}
	ctx = httptrace.WithClientTrace(ctx, trace)
	out := quickcheck.CheckTarget(ctx, client, quickcheck.Target{Name: target.Name, URL: target.URL, Method: http.MethodGet})
	sample := routeplan.Sample{Success: out.Success, Reachable: out.Reachable, TLSVerified: out.Reachable, Status: out.Status, LatencyMS: out.Took.Milliseconds(), TCPMS: tcpMS.Load(), TLSMS: tlsMS.Load(), BodyBytes: out.BodyBytes}
	if !out.Reachable || (!out.Success && strings.Contains(out.Detail, "body incomplete")) {
		sample.Error = out.Detail
	}
	return sample
}

func routeProbeTLS(upstream smartproxy.Upstream, privateDir string) *tls.Config {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if upstream.Takeover != nil {
		// The internal probe explicitly opts into this app's existing public CA.
		// This does not install it, broaden its constraints or imply that native
		// X/Instagram clients trust a user CA. Upstream TLS remains verified.
		if cert := routeTargetsPublicCA(privateDir); cert != nil {
			roots, err := x509.SystemCertPool()
			if err != nil {
				roots = x509.NewCertPool()
			}
			roots.AddCert(cert)
			config.RootCAs = roots
		}
	}
	return config
}
