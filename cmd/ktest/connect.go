package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Nishef1/ktest/internal/dnscheck"
	"github.com/Nishef1/ktest/internal/edges"
	"github.com/Nishef1/ktest/internal/front"
	"github.com/Nishef1/ktest/internal/quickcheck"
	"github.com/Nishef1/ktest/internal/revive"
	"github.com/Nishef1/ktest/internal/smartproxy"
	"github.com/Nishef1/ktest/internal/systemtun"
	"github.com/Nishef1/ktest/internal/wstunnel"
)

const (
	connectListenDefault = "127.0.0.1:10800"
	connectHTTPDefault   = "127.0.0.1:10801"
	connectPort          = 10800
	connectHTTPPort      = 10801
	connectXrayBPort     = xrayPort // 10808
	connectXrayAPort     = 10811
	connectByeDPIBase    = 10812
)

// pathCore is one upstream core run side by side with the others.
type pathCore struct {
	name   string
	port   int
	launch launcher
	run    *runningCore
	logs   *tailBuffer
	// localDNS: the core resolves names with the system resolver.
	localDNS    bool
	localBypass bool // explicit ktest-managed, IP-preserving packet shaping
}

func xrayLauncher(base, variant string, port int, out io.Writer) (launcher, error) {
	core := filepath.Join(base, "cores")
	bin := filepath.Join(core, "xray")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	profile := filepath.Join(base, "profiles", "Serverless-for-Iran.json")
	for _, f := range []string{bin, profile} {
		if !fileOK(f) {
			return nil, fmt.Errorf("missing %s", f)
		}
	}
	return func(ctx context.Context, dns *dnscheck.Result) error {
		return revive.Run(ctx, revive.Config{XrayBinary: bin, Profile: profile, Variant: variant, AssetDir: core, Port: port, Output: out, DNS: dns})
	}, nil
}

func localXrayLauncher(base, variant string, port int, out io.Writer) (launcher, error) {
	core := filepath.Join(base, "cores")
	bin := filepath.Join(core, "xray")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if !fileOK(bin) {
		return nil, fmt.Errorf("missing %s", bin)
	}
	return func(ctx context.Context, _ *dnscheck.Result) error {
		return revive.RunLocalTCP(ctx, revive.Config{XrayBinary: bin, Variant: variant, AssetDir: core, Port: port, Output: out})
	}, nil
}

// connectOptions configures one connect session (CLI or menu). The defaults are
// the product; every field is for experiments.
type connectOptions struct {
	base                string
	mode                ConnectionMode
	listen              string
	strategies          int
	noXray              bool
	noSelf              bool
	noDoH               bool
	noDirect            bool
	noFront             bool
	noWarp              bool
	noHTTP              bool
	httpListen          string
	exitSocks           string
	aiExtra             string
	windscribeCLI       string
	windscribeReconnect bool
	ws                  wsOptions
	tun                 bool
	cert                bool
	forceFront          bool
	stagger             time.Duration
	firstByte           time.Duration
	ready               time.Duration
	verbose             bool
	stopHint            string
	aetherMethod        string
}

// Strict tunnel-only modes cannot safely probe sites before verifying an exit.
func canProbeSites(mode ConnectionMode, verifiedExit bool) bool {
	return !mode.exitOnly() || verifiedExit
}

// A local MITM CA powers optional website fronting, not WARP/Aether tunnels.
// Suggesting its installation in strict exit-only modes grants unnecessary trust.
func frontCARelevant(o connectOptions) bool {
	return !o.mode.exitOnly() && o.mode != ModeWindscribe && !o.noFront
}

func defaultConnectOptions(base string) connectOptions {
	return connectOptions{
		base: base, mode: ModeBalanced, listen: connectListenDefault, httpListen: connectHTTPDefault, strategies: 12, windscribeReconnect: true,
		tun:     runtime.GOOS == "windows",
		ws:      wsOptions{direct: true, sni: defaultWindscribeSNIs},
		stagger: 250 * time.Millisecond, firstByte: 5 * time.Second, ready: 30 * time.Second,
		stopHint: "Press Ctrl+C to disconnect",
	}
}

// connectFlagSet is shared by interactive and command-line preferences.
func connectFlagSet(o *connectOptions) *flag.FlagSet {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.StringVar(&o.base, "base", o.base, "portable folder holding cores/ and profiles/")
	fs.StringVar((*string)(&o.mode), "mode", string(o.mode), "balanced (AI protected), fast, windscribe, windscribe-aether, aether, psiphon, tor")
	fs.StringVar(&o.windscribeCLI, "windscribe-cli", o.windscribeCLI, "absolute path to Windscribe desktop CLI (auto-detected on Windows)")
	fs.BoolVar(&o.windscribeReconnect, "windscribe-auto-reconnect", o.windscribeReconnect, "reconnect last selected Windscribe location after verified bootstrap becomes available")
	fs.BoolVar(&o.ws.direct, "windscribe-wstunnel", o.ws.direct, "Windscribe mode: race WStunnel and Stealth straight to the Windscribe node with chosen SNIs")
	fs.StringVar(&o.ws.sni, "windscribe-wstunnel-sni", o.ws.sni, "comma-separated TLS SNIs raced on the direct carriers")
	fs.StringVar(&o.ws.serverIP, "windscribe-wstunnel-ip", o.ws.serverIP, "explicit Windscribe WStunnel server IP (default: addresses advertised for the same node by Windscribe)")
	fs.StringVar(&o.ws.path, "windscribe-wstunnel-path", o.ws.path, "WStunnel path (default "+wstunnel.DefaultPath+")")
	fs.StringVar(&o.ws.cdnHost, "windscribe-cdn", o.ws.cdnHost, "your Cloudflare hostname whose proxied DNS record points at a Windscribe WStunnel IP; tried first")
	fs.StringVar(&o.ws.cdnSNI, "windscribe-cdn-sni", o.ws.cdnSNI, "TLS SNI for the CDN carrier (default: -windscribe-cdn)")
	fs.StringVar(&o.ws.cdnEdges, "windscribe-cdn-edge", o.ws.cdnEdges, "comma-separated CDN edge IPs (default: scan Cloudflare for edges that reach -windscribe-cdn)")
	fs.StringVar(&o.listen, "listen", o.listen, "loopback SOCKS5 address for your applications")
	fs.IntVar(&o.strategies, "strategies", o.strategies, "how many ByeDPI strategies from profiles/byedpi-strategies.txt to run (0 = none)")
	fs.BoolVar(&o.noXray, "no-xray", o.noXray, "do not run Xray profiles (including generated local TCP methods in Windscribe mode)")
	fs.BoolVar(&o.noSelf, "no-self", o.noSelf, "do not add ktest's built-in ClientHello cutting paths")
	fs.BoolVar(&o.noDoH, "no-doh", o.noDoH, "never use encrypted DNS (system DNS only)")
	fs.BoolVar(&o.noDirect, "no-direct", o.noDirect, "do not race the plain, uncut connection")
	fs.BoolVar(&o.noFront, "no-front", o.noFront, "do not use domain fronting even if the ktest CA is trusted")
	fs.BoolVar(&o.noWarp, "no-warp", o.noWarp, "do not start Aether's WARP/Psiphon exit search even if it is enabled")
	fs.StringVar(&o.aetherMethod, "aether-method", o.aetherMethod, "auto, masque-h2, masque-h3, wireguard, gool-h2, gool-h3, wiw, mim-h2, mim-h3, psiphon, psiphon-cdn")
	fs.BoolVar(&o.noHTTP, "no-http", o.noHTTP, "disable the local HTTP proxy for Windscribe")
	fs.StringVar(&o.httpListen, "http-listen", o.httpListen, "loopback HTTP proxy for Windscribe Proxy Settings")
	fs.StringVar(&o.exitSocks, "exit-socks", o.exitSocks, "optional loopback SOCKS5 exit (Tor, Psiphon or authorized Worker), TCP only")
	fs.StringVar(&o.aiExtra, "ai-extra", o.aiExtra, "additional AI hostnames, comma-separated; matched names require verified foreign exit")
	fs.BoolVar(&o.tun, "tun", o.tun, "route the whole system through ktest (Windows; asks for Administrator)")
	fs.BoolVar(&o.cert, "cert", o.cert, "set up or renew the local certificate for domain fronting first (Windows asks you to confirm)")
	fs.BoolVar(&o.forceFront, "front", o.forceFront, "use domain fronting even when the system does not report the ktest CA as trusted (Firefox with its own store)")
	fs.DurationVar(&o.stagger, "stagger", o.stagger, "maximum preferred-path head start before the small fallback wave")
	fs.DurationVar(&o.firstByte, "first-byte", o.firstByte, "how long a path may take to answer the TLS ClientHello")
	fs.DurationVar(&o.ready, "ready", o.ready, "how long to wait for each core's local port")
	fs.BoolVar(&o.verbose, "v", o.verbose, "log every path decision and core output")
	return fs
}

func validateConnectOptions(o connectOptions) error {
	host, port, err := net.SplitHostPort(o.listen)
	if err != nil || port == "" || (host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback())) {
		return errors.New("-listen must be a loopback host:port")
	}
	if _, err := parseConnectionMode(string(o.mode)); err != nil {
		return err
	}
	if o.mode == ModePsiphon && o.exitSocks != "" {
		return errors.New("Aether to Psiphon forbids -exit-socks: only managed Psiphon profiles may be used")
	}
	if o.mode.isWindscribe() && o.exitSocks != "" {
		return errors.New("Windscribe mode forbids -exit-socks: no foreign proxy/VPN exit may be used")
	}
	if err := o.ws.validate(); err != nil {
		return err
	}
	if o.mode != ModeWindscribe && o.ws.cdnHost != "" {
		return errors.New("-windscribe-cdn only applies to -mode windscribe")
	}
	if o.mode.isWindscribe() && o.tun {
		return errors.New("Windscribe bootstrap cannot run with ktest -tun; stop ktest's whole-PC tunnel first")
	}
	if o.strategies < 0 || o.strategies > 12 {
		return errors.New("-strategies must be 0..12")
	}
	if !validAetherMethod(o.aetherMethod) {
		return errors.New("unknown -aether-method; use connect -h for supported methods")
	}
	if o.mode == ModeWindscribeAether && (o.noWarp || strings.HasPrefix(o.aetherMethod, "psiphon")) {
		return errors.New("Windscribe through Aether requires WARP; -no-warp and Psiphon methods are not allowed")
	}
	if o.mode == ModeWindscribeAether && o.noHTTP {
		return errors.New("Windscribe through Aether requires the local HTTP CONNECT bridge")
	}
	if o.mode == ModePsiphon && o.aetherMethod != "" && o.aetherMethod != "auto" && !strings.HasPrefix(o.aetherMethod, "psiphon") {
		return errors.New("Psiphon mode requires a Psiphon method or auto")
	}
	return nil
}

// runConnect is `ktest connect`: connect now, with the defaults.
func runConnect(args []string) int {
	// An elevated handoff supplies every effective option. Do not read or
	// overwrite a different administrator's preferences in that child process.
	handoff := len(args) > 0 && args[0] == elevatedSessionArg
	settings, path, o := userSettings{}, "", defaultConnectOptions(defaultBase())
	var settingsErr error
	if handoff {
		args = args[1:]
	} else {
		settings, path, o, settingsErr = loadPreferences(o.base)
	}
	u := newTerm(os.Stdout)
	if settingsErr != nil {
		u.Line(toneWarn, "Saved settings unavailable; using defaults: %v", settingsErr)
	}
	fs := connectFlagSet(&o)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: ktest connect [-v]   (all other flags are for experiments; see -h)")
		return 2
	}
	mode, err := parseConnectionMode(string(o.mode))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	// Retain other policies' saved choices, but do not apply them to this one.
	// Explicit incompatible flags still reach validation and are rejected.
	explicit := map[string]string{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = f.Value.String() })
	o = optionsForMode(o, mode)
	for name, value := range explicit {
		_ = fs.Set(name, value) // already parsed successfully above
	}
	o.mode = mode
	if err := validateConnectOptions(o); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if !handoff && settings.rememberFlags(fs) {
		if err := saveSettings(path, settings); err != nil {
			u.Line(toneWarn, "Settings were not saved: %v", err)
		}
	}
	if o.cert && !ensureCert(u) {
		return 1
	}
	if o.tun && !systemtun.IsAdmin() {
		return relaunchElevated(u, o)
	}
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	return connectSession(ctx, o, nil, u)
}

// siteEvents prints the live feed: one line per site when its winning path is
// first known or changes, and at most one failure line per site every 20 s.
type siteEvents struct {
	t           *term
	last        map[string]string
	failedAt    map[string]time.Time
	ok, fail    atomic.Int64
	tcpOnly     atomic.Int64
	prepared    atomic.Int64
	earlyClosed atomic.Int64
	rejected    atomic.Int64
	routes      map[string]*routeSelection
	setupTotal  time.Duration
	setupMax    time.Duration
	slow        int
	dropped     *atomic.Int64
	fronts      *hostAggregate
	verbose     bool
}

type routeSelection struct {
	name  string
	count int
	setup time.Duration
}

func (s *siteEvents) print(e smartproxy.Event) {
	t := s.t
	if s.last == nil {
		s.last = make(map[string]string)
	}
	if s.failedAt == nil {
		s.failedAt = make(map[string]time.Time)
	}
	host := e.Host
	if host == "" {
		host = e.Site
	}
	key := net.JoinHostPort(strings.ToLower(strings.TrimSuffix(host, ".")), e.Port)
	target := host
	if e.Port != "" && e.Port != "443" {
		target = net.JoinHostPort(host, e.Port)
	}
	if e.EarlyClose {
		s.earlyClosed.Add(1)
		if time.Since(s.failedAt[key+"|early"]) >= 20*time.Second {
			s.failedAt[key+"|early"] = time.Now()
			t.Line(toneWarn, "%s · %s · %s", t.Bold(target), t.Yellow("EARLY CLOSE"), e.Path)
			s.detail(e.Err)
		}
		return
	}
	if e.OK || e.TCPOnly {
		if s.routes == nil {
			s.routes = make(map[string]*routeSelection)
		}
		r := s.routes[e.Path]
		if r == nil {
			r = &routeSelection{name: e.Path}
			s.routes[e.Path] = r
		}
		r.count++
		r.setup += e.Took
		s.setupTotal += e.Took
		s.setupMax = max(s.setupMax, e.Took)
		if e.Took >= time.Second {
			s.slow++
		}
	}
	if e.TCPOnly {
		s.tcpOnly.Add(1)
		if isWindscribeCarrier(e.Path) {
			path := e.Path
			if strings.HasPrefix(path, "raw OpenVPN") {
				path += " entry=" + e.Host
			}
			t.Line(toneInfo, "requested=%s · %s · %s · %s", t.Bold(e.Host), t.Cyan("OPENVPN REPLY"), path, t.Dim(shortDur(e.Took)))
			t.Note("Control framing only; VPN authentication and data not verified.")
			return
		}
		if s.last[key] == e.Path+"|TCP OPEN" {
			return
		}
		s.last[key] = e.Path + "|TCP OPEN"
		t.Line(toneInfo, "%s · %s · %s · %s", t.Bold(target), t.Cyan("TCP OPEN"), e.Path, t.Dim(shortDur(e.Took)))
		t.Note("TCP connected; no application response was checked before selection.")
		return
	}
	if e.Rejected {
		s.rejected.Add(1)
		if time.Since(s.failedAt[key]) >= 20*time.Second {
			s.failedAt[key] = time.Now()
			reason := e.Err
			if i := strings.LastIndex(reason, "): "); !s.verbose && i >= 0 {
				reason = reason[i+3:]
			}
			t.Line(toneWarn, "%s · %s", t.Bold(target), t.Yellow("CERTIFICATE REFUSED"))
			s.detail(reason)
			t.Note("Another route will be preferred on the next connection.")
		}
		return
	}
	if e.OK {
		slow := e.Took >= time.Second
		state := "ANSWERED"
		if e.Prepared {
			s.prepared.Add(1)
			state = "ROUTE READY"
		} else {
			s.ok.Add(1)
		}
		if e.TLSResponse {
			state = "TLS RESPONSE"
		}
		identity := fmt.Sprintf("%s|%s|%t", e.Path, state, slow)
		if s.last[key] == identity {
			return
		}
		s.last[key] = identity
		k := toneOK
		if slow {
			k = toneWarn
		}
		path := e.Path
		if e.Egress != "" {
			path += " · " + e.Egress
		}
		t.Line(k, "%s · %s · %s · %s", t.Bold(target), t.tinted(k, state), t.tinted(k, shortDur(e.Took)), path)
		return
	}
	s.fail.Add(1)
	if time.Since(s.failedAt[key]) < 20*time.Second {
		return
	}
	s.failedAt[key] = time.Now()
	reason := e.Err
	if i := strings.LastIndex(reason, ": "); !s.verbose && i >= 0 && len(reason) > 60 {
		reason = reason[i+2:]
	}
	t.Line(toneFail, "%s · %s", t.Bold(target), t.Red("NO REPLY"))
	s.detail(reason)
}

func (s *siteEvents) detail(reason string) {
	if s.verbose {
		s.t.Note("%s", reason)
		return
	}
	s.t.Note("%s", trimDetail(reason))
	if len([]rune(reason)) > 70 {
		s.t.Note("Use -v for the full error.")
	}
}

// connectSession runs until ctx ends. preflight may carry a Google DNS check
// the caller already measured.
func connectSession(ctx context.Context, o connectOptions, preflight *dnscheck.Result, t *term) int {
	t.Heading("connect", "Routing mode: "+string(o.mode))
	t.Note("Coverage: %s", connectionCoverage(o))
	t.Note("%s", o.mode.message())
	if o.mode == ModeWindscribeAether {
		if err := validateConnectOptions(o); err != nil {
			t.Line(toneFail, "%v", err)
			return 2
		}
	}
	if o.mode == ModePsiphon && o.exitSocks != "" {
		t.Line(toneFail, "Aether to Psiphon forbids external SOCKS exits (-exit-socks)")
		return 2
	}
	if o.mode == ModeWindscribe {
		if o.exitSocks != "" {
			t.Line(toneFail, "Windscribe local-only mode forbids external SOCKS exits (-exit-socks)")
			return 2
		}
		// Mode policy is non-negotiable. Never load Aether, Psiphon, WARP,
		// Tor or foreign SOCKS, even when the user enabled them in Setup.
		o.noWarp = true
	}
	if o.mode.isWindscribe() && o.tun {
		t.Line(toneFail, "Windscribe bootstrap cannot share ktest's system-wide TUN; run without -tun")
		return 2
	}
	if o.mode.isWindscribe() && runtime.GOOS == "windows" {
		if names := activeKtestTUNs(); len(names) > 0 {
			t.Line(toneFail, "A ktest TUN is still active (%s). Stop whole-PC mode before connecting Windscribe.", strings.Join(names, ", "))
			return 2
		}
	}
	monitor := startWindscribeMonitor(ctx, o, t)
	if o.mode == ModeWindscribeAether && monitor == nil {
		t.Line(toneFail, "Windscribe through Aether needs a trusted CLI state; check Windscribe/login before starting a second tunnel")
		return 1
	}
	if monitor != nil && (monitor.Connected() || (o.mode == ModeWindscribeAether && monitor.State() != windscribeDisconnected)) {
		t.Note("Windscribe is %s. Standing by until the official CLI confirms disconnect; existing VPN is left running.", monitor.State())
		if !monitor.waitDisconnected(ctx) {
			return 0
		}
	}
	aiRules, aiErr := smartproxy.NewAIDomainRules(o.aiExtra)
	if aiErr != nil {
		t.Line(toneFail, "%v", aiErr)
		return 2
	}

	// 1. The network, before any core starts.
	step := t.Progress("Checking the network", 2)
	ip, poisoned, derr := systemDNS(ctx, "www.youtube.com")
	step.Set(1, "system DNS")
	var dns dnscheck.Result
	if preflight != nil {
		dns = *preflight
	} else {
		dns = dnscheck.CheckGoogleDNS(ctx)
	}
	step.Set(2, "")
	if ctx.Err() != nil {
		return 0
	}
	k := toneOK
	if poisoned || derr != nil || (!dns.UDP && !dns.TCP) {
		k = toneWarn
	}
	step.Finish(k, "")
	switch {
	case poisoned:
		t.Note("system DNS appears intercepted: www.youtube.com → %s (private/block-page address); encrypted DNS will be attempted, not yet verified", ip)
	case derr != nil:
		t.Note("system DNS did not answer for www.youtube.com")
	default:
		t.Note("system DNS looks sane: www.youtube.com → %s", ip)
	}
	if !dns.UDP && !dns.TCP {
		t.Note("public resolver 8.8.8.8 is unreachable (UDP and TCP), so it is not relied on")
	}

	// The listen address is needed at the end; find out now, not after the cores
	// have been started.
	if lis, err := net.Listen("tcp", o.listen); err != nil {
		t.Println("")
		t.Box("CANNOT LISTEN", toneFail, []string{o.listen + " is already in use.", "Close the other ktest or proxy using it, or pass -listen 127.0.0.1:<other port>."})
		return 1
	} else {
		_ = lis.Close()
	}

	// 2. The cores that carry the external paths.
	var cores []*pathCore
	var skipped []string
	add := func(name string, port int, localDNS, localBypass bool, mk func(io.Writer) (launcher, error)) {
		c := &pathCore{name: name, port: port, logs: &tailBuffer{max: 4096}, localDNS: localDNS, localBypass: localBypass}
		if o.verbose {
			c.logs.tee = os.Stderr
		}
		l, err := mk(c.logs)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", name, err))
			return
		}
		c.launch = l
		cores = append(cores, c)
	}
	if !o.noXray && !o.mode.exitOnly() {
		// Imported Xray profiles may contain foreign outbound proxies. Do
		// not trust a filename containing "fragment" as identity-preserving.
		for _, x := range []struct {
			variant string
			port    int
		}{{"B", connectXrayBPort}, {"A", connectXrayAPort}} {
			x := x
			if o.mode == ModeWindscribe {
				// Only our generated freedom/fragment configuration is trusted.
				// Imported subscription profiles remain prohibited in this mode.
				add("Xray local TCP fragment "+x.variant, x.port, true, true, func(w io.Writer) (launcher, error) { return localXrayLauncher(o.base, x.variant, x.port, w) })
			} else {
				add("Xray fragment "+x.variant, x.port, true, false, func(w io.Writer) (launcher, error) { return xrayLauncher(o.base, x.variant, x.port, w) })
			}
		}
	}
	if o.strategies > 0 && !o.mode.exitOnly() {
		bin := byeDPIBinary(o.base)
		list, _, err := loadStrategies(o.base)
		switch {
		case !fileOK(bin):
			skipped = append(skipped, "ByeDPI: missing "+bin)
		case err != nil:
			skipped = append(skipped, "ByeDPI strategies: "+err.Error())
		default:
			if len(list) > o.strategies {
				list = list[:o.strategies]
			}
			for i, s := range list {
				s, port := s, connectByeDPIBase+i
				add("ByeDPI "+s.Label, port, true, true, func(w io.Writer) (launcher, error) { return byeDPILauncher(bin, port, s.Args, w), nil })
			}
		}
	}

	var live []*pathCore
	for _, c := range cores {
		if err := portFree(c.port); err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", c.name, err))
			continue
		}
		cctx, cancel := context.WithCancel(ctx)
		rc := &runningCore{cancel: cancel, done: make(chan struct{})}
		c.run = rc
		go func(c *pathCore) {
			rc.err = c.launch(cctx, &dns)
			close(rc.done)
		}(c)
		live = append(live, c)
	}
	defer func() {
		for _, c := range live { // ask all to end first, then wait: stops in parallel
			c.run.cancel()
		}
		for _, c := range live {
			c.run.stop()
		}
	}()

	var up []*pathCore
	var failed []string
	if len(live) > 0 {
		progressLabel := "Starting external paths"
		if o.mode == ModeWindscribe {
			progressLabel = "Starting LOCAL anti-DPI paths"
		}
		prog := t.Progress(progressLabel, len(live))
		var mu sync.Mutex
		var wg sync.WaitGroup
		finished := 0
		for _, c := range live {
			wg.Add(1)
			go func(c *pathCore) {
				defer wg.Done()
				ok := waitForPort(ctx, c.run.done, c.port, o.ready)
				mu.Lock()
				defer mu.Unlock()
				finished++
				if ok {
					up = append(up, c)
				} else {
					note := "port did not open"
					select {
					case <-c.run.done:
						if c.run.err != nil {
							note = c.run.err.Error()
						}
					default:
						if l := c.logs.lastLine(); l != "" {
							note += "; " + l
						}
					}
					failed = append(failed, c.name+": "+note)
				}
				prog.Set(finished, fmt.Sprintf("%d ready", len(up)))
			}(c)
		}
		wg.Wait()
		if ctx.Err() != nil {
			return 0
		}
		kind := toneOK
		if len(up) < len(live) {
			kind = toneWarn
		}
		if len(up) == 0 {
			kind = toneFail
		}
		prog.Finish(kind, fmt.Sprintf("%d of %d ready", len(up), len(live)))
	}
	for _, s := range append(skipped, failed...) {
		t.Note("skipped %s", s)
	}
	sort.Slice(up, func(i, j int) bool { return up[i].port < up[j].port })

	// 3. Assemble the race. Initial order is the initial head start: the uncut
	// baseline first, so unblocked sites never pay for a cut ClientHello.
	var ups []smartproxy.Upstream
	if !o.noDirect && !o.mode.exitOnly() && o.mode != ModeWindscribe {
		ups = append(ups, smartproxy.PlainUpstreams()...)
	}
	for _, c := range up {
		ups = append(ups, smartproxy.Upstream{
			Name: c.name, Addr: fmt.Sprintf("127.0.0.1:%d", c.port),
			LocalDNS: c.localDNS, SoftResolve: strings.HasPrefix(c.name, "Xray") && !c.localBypass,
			Rank: 2, LocalBypass: c.localBypass,
		})
	}
	if !o.noSelf && !o.mode.exitOnly() {
		ups = append(ups, smartproxy.DesyncUpstreams()...)
	}
	// An independent, already-running TCP exit (e.g. Tor, Psiphon or a
	// user-owned serverless Worker) can carry Windscribe's TCP bootstrap
	// when all direct anti-DPI routes fail. Never loop back into ktest.
	if o.exitSocks != "" {
		exit, e := net.ResolveTCPAddr("tcp", o.exitSocks)
		socks, _ := net.ResolveTCPAddr("tcp", o.listen)
		http, _ := net.ResolveTCPAddr("tcp", o.httpListen)
		if e != nil || exit.IP == nil || !exit.IP.IsLoopback() || exit.Port == 0 ||
			(socks != nil && exit.Port == socks.Port) || (http != nil && exit.Port == http.Port) {
			t.Line(toneFail, "-exit-socks must be a distinct loopback SOCKS5 port (not ktest's own listeners)")
			return 2
		}
		ip, country, checked := probeForeignExit(ctx, o.exitSocks)
		if o.mode == ModeTor && checked == nil {
			checked = probeTorExit(ctx, o.exitSocks)
		}
		if checked == nil {
			t.Note("External SOCKS exit verified outside Iran: %s (%s)", ip, country)
		} else {
			t.Note("External SOCKS exit is not permitted for protected AI sites: %v", checked)
		}
		ups = append(ups, smartproxy.Upstream{
			Name: "External SOCKS exit", Addr: o.exitSocks, Exit: true, AIEligible: checked == nil, Late: o.mode != ModeFast && !o.mode.exitOnly(), Rank: 3,
		})
	}
	if len(ups) == 0 && !o.mode.exitOnly() && !o.forceFront {
		t.Box("NOTHING TO RUN", toneFail, []string{"No path is available. Extract the complete portable ZIP (cores/ and profiles/)", "or run `ktest doctor`."})
		return 1
	}
	events := make(chan smartproxy.Event, 256)
	var dropped atomic.Int64
	var activity atomic.Uint64
	var liveProxy atomic.Pointer[smartproxy.Proxy]
	cfg := smartproxy.Config{
		Upstreams: ups, Stagger: o.stagger, FirstByteTimeout: o.firstByte,
		VerifyExit: func(ctx context.Context, u smartproxy.Upstream) error {
			_, _, err := probeForeignExit(ctx, u.Addr)
			return err
		},
		VerifyCarrier: func(ctx context.Context, u smartproxy.Upstream) error {
			_, _, err := probeExitLocation(ctx, u.Addr)
			return err
		},
		OnEvent: func(e smartproxy.Event) {
			if !trackUserEvent(&activity, e) {
				return
			}
			select {
			case events <- e:
			default:
				dropped.Add(1)
			}
		},
	}
	o.mode.configure(&cfg, aiRules)
	if o.mode == ModeWindscribe {
		cfg.RejectExits = true // guard both initial and dynamically added routes
		cfg.LocalOnly = true   // also reject plain/unknown relays and takeovers
	}
	logDNS := func(f string, a ...any) {
		if o.verbose {
			t.Printf("    %s\n", t.Dim("dns: "+fmt.Sprintf(f, a...)))
		}
	}
	var dohA, dohAAAA smartproxy.Resolver
	dnsGeneration := func() uint64 {
		if p := liveProxy.Load(); p != nil {
			_, generation := p.ExitCarriers()
			return generation
		}
		return 0
	}
	if !o.noDoH {
		var carriers []string
		for _, u := range ups {
			if u.Addr != "" {
				carriers = append(carriers, u.Addr)
			}
		}
		dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
			if p := liveProxy.Load(); p != nil {
				if exits, _ := p.ExitCarriers(); len(exits) > 0 {
					// A bare TCP acknowledgement on a filtered direct route
					// must not beat the newly working tunnel and fail at TLS.
					return raceDialPaths(ctx, exits, addr, false)
				}
			}
			return raceDial(ctx, carriers, addr)
		}
		// The public resolvers are filtered by address on many networks; the ECH
		// route to Cloudflare's resolver is not, and needs neither DNS nor a path.
		endpoints := append(append([]smartproxy.DoHEndpoint(nil), smartproxy.DefaultDoH...), echDoHEndpoint())
		dohA = smartproxy.NewDoH(endpoints, dial, nil)
		dohAAAA = smartproxy.NewDoHType(endpoints, dial, nil, "AAAA")
	}
	cfg.Resolve = smartproxy.NewTrusted(smartproxy.TrustedOptions{DoH: dohA, DoHGeneration: dnsGeneration, Logf: logDNS})
	cfg.Resolve6 = smartproxy.NewTrusted(smartproxy.TrustedOptions{DoH: dohAAAA, DoHGeneration: dnsGeneration, IPv6: true, Logf: logDNS})

	// Domain fronting is a takeover path: it needs the application to trust the
	// ktest CA, so it is only added when the system says it does.
	var fronter *front.Fronter
	frontHistory := &hostAggregate{rows: map[string]*hostRow{}}
	frontNote := ""
	if !o.mode.exitOnly() && o.mode != ModeWindscribe {
		// A CDN front can act as an egress/HTTP takeover; its public-IP
		// semantics are not guaranteed. Local-only means no CDN relay.
		fronter, frontNote = newFronter(o, cfg.Resolve, t, logDNS, frontHistory)
	}
	if fronter != nil {
		cfg.Upstreams = append(cfg.Upstreams, fronter.Upstream())
	}
	if o.verbose {
		cfg.Logf = func(f string, a ...any) { t.Printf("    %s\n", t.Dim(fmt.Sprintf(f, a...))) }
	}
	proxy, err := smartproxy.New(cfg)
	if err != nil {
		t.Line(toneFail, "%v", err)
		return 2
	}
	liveProxy.Store(proxy)
	l, err := net.Listen("tcp", o.listen)
	if err != nil {
		t.Line(toneFail, "cannot listen on %s: %v", o.listen, err)
		return 1
	}
	defer l.Close()
	monitor.attach(proxy)
	_, portText, _ := net.SplitHostPort(l.Addr().String())
	var lport int
	fmt.Sscanf(portText, "%d", &lport)
	go func() { _ = proxy.Serve(ctx, l) }()
	probePort := 0
	if !o.mode.isWindscribe() {
		probes, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Line(toneFail, "cannot start internal site checks: %v", err)
			return 1
		}
		defer probes.Close()
		probePort = probes.Addr().(*net.TCPAddr).Port
		go func() { _ = proxy.ServeProbes(ctx, probes) }()
	}
	// Windscribe accepts an HTTP upstream proxy, while Connect speaks SOCKS5.
	// The HTTP bridge shares Connect's learned path selection without changing
	// system DNS, routing, or trust stores.
	httpAddr := ""
	if !o.noHTTP {
		var stopHTTP func()
		if o.mode.isWindscribe() {
			dial := proxy.DialWindscribeLocal
			if o.mode == ModeWindscribeAether {
				dial = proxy.DialExitCarrier
			}
			if o.mode == ModeWindscribe && o.ws.enabled() {
				logf := cfg.Logf
				if logf == nil {
					logf = func(string, ...any) {}
				}
				// API TLS must use the existing first-response race: a local
				// SOCKS acknowledgement alone can select a silent Xray path.
				apiDial := func(ctx context.Context, host, port string) (net.Conn, error) {
					return smartproxy.DialVia(ctx, l.Addr().String(), host, port, 8*time.Second)
				}
				bridge := newWSBridge(o.ws, apiDial, cfg.OnEvent, logf)
				bridge.carrierLocal = proxy.DialWindscribeCarrier
				bridge.catalog = newWSNodeCatalog()
				cachePath := filepath.Join(o.base, "cache", "windscribe-nodes.json")
				bridge.catalog.load(cachePath)
				catalogTransport := &http.Transport{DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
					host, port, err := net.SplitHostPort(addr)
					if err != nil {
						return nil, err
					}
					return apiDial(ctx, host, port)
				}}
				defer catalogTransport.CloseIdleConnections()
				catalogClient := &http.Client{Transport: catalogTransport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
					return errors.New("Windscribe node-list redirects are not accepted")
				}}
				go bridge.catalog.run(ctx, catalogClient, cachePath, logf)
				bridge.note = func(f string, a ...any) { t.Line(toneInfo, f, a...) }
				if o.ws.cdnHost != "" && o.ws.cdnEdges == "" {
					if ips, err := edges.CloudflareCandidates(300); err == nil {
						t.Line(toneInfo, "Scanning %d Cloudflare IPs for edges that reach %s", len(ips), o.ws.cdnHost)
						go bridge.scanCDNEdges(ctx, ips)
					}
				}
				dial = bridge.Dial
			}
			httpAddr, stopHTTP, err = startHTTPBridge(ctx, o.httpListen, l.Addr().String(), dial)
		} else {
			httpAddr, stopHTTP, err = startHTTPBridge(ctx, o.httpListen, l.Addr().String())
		}
		if err != nil {
			t.Note("Windscribe HTTP proxy unavailable: %v (normal SOCKS5 still works)", err)
		} else {
			defer stopHTTP()
		}
	}
	var warpNote string
	var currentExitStatus func() string
	var stopWarp func()
	if o.mode == ModeTor {
		warpNote, stopWarp = startTor(ctx, o, proxy, t)
	} else if o.mode == ModeWindscribe {
		warpNote = "disabled: local anti-DPI only; Psiphon/Aether/WARP/Tor and foreign exits prohibited"
		stopWarp = func() {}
	} else {
		currentExitStatus, stopWarp = startWarp(ctx, o, proxy, &dns, t, monitor)
	}
	defer stopWarp()

	// 4. Windscribe owns the network while it is connected. In that state,
	// don't run extra local website probes which could disturb its data plane.
	var proxied []quickcheck.Result
	var compared []quickcheck.Assessment
	verdict := toneInfo
	if o.mode.isWindscribe() {
		t.Note("Windscribe mode skips unrelated website tests; only the selected VPN carrier is prepared")
	} else if monitor == nil || !monitor.Connected() {
		if o.mode.exitOnly() && !proxy.HasVerifiedExit() {
			wstep := t.Progress("Waiting for a verified foreign exit before site checks", 1)
			wctx, wcancel := context.WithTimeout(ctx, 20*time.Second)
			available := waitForVerifiedExit(wctx, proxy)
			wcancel()
			if ctx.Err() != nil {
				return 0
			}
			if available {
				wstep.Finish(toneOK, "foreign route available")
			} else {
				wstep.Finish(toneWarn, "still searching; no direct fallback will be used")
			}
		}
		if !canProbeSites(o.mode, proxy.HasVerifiedExit()) {
			// Never turn "no exit yet" into five fabricated site failures.
			// In strict modes the proxy must remain fail-closed while discovery runs.
			verdict = toneFail
			t.Note("Site checks deferred: no verified foreign exit; discovery continues without direct fallback")
		} else {
			vstep := t.Progress("Checking representative sites and learning routes", 1)
			vctx, vcancel := context.WithTimeout(ctx, 30*time.Second)
			proxied, compared = measure(vctx, probePort)
			vcancel()
			if ctx.Err() != nil {
				return 0
			}
			passedNow := proxiedPassCount(proxied)
			verdict = toneOK
			switch {
			case passedNow == 0:
				verdict = toneFail
			case passedNow < len(proxied):
				verdict = toneWarn
			}
			vstep.Finish(verdict, fmt.Sprintf("%d of %d reachable through ktest", passedNow, len(proxied)))
		}
	} else {
		t.Note("Windscribe active: skipping extra website probes")
	}
	passed := proxiedPassCount(proxied)
	bypassed := 0
	for _, c := range compared {
		switch c.Kind {
		case "not_checked":
			t.Line(toneInfo, "%-9s %s", c.Target, "not checked within the shared startup budget")
		case "service_response":
			t.Line(toneWarn, "%-9s %s", c.Target, c.Detail)
		case "candidate":
			bypassed++
			t.Line(toneOK, "%-9s %s", c.Target, "blocked directly, open through ktest "+t.Bold("(bypass confirmed)"))
		case "already_open":
			t.Line(toneInfo, "%-9s %s", c.Target, "open through ktest and also directly")
		case "proxy_regression":
			t.Line(toneWarn, "%-9s %s", c.Target, "open directly but failing through ktest (a path or DNS problem)")
		case "baseline_unknown":
			t.Line(toneInfo, "%-9s %s", c.Target, "open through ktest (direct check did not finish)")
		default:
			t.Line(toneFail, "%-9s %s", c.Target, "not reachable through ktest "+t.Dim(trimDetail(c.Detail)))
		}
	}

	// Verify requested coverage before announcing READY.
	coverage := "Proxy · configure SOCKS5/HTTP in each application"
	if o.mode.isWindscribe() {
		coverage = "Windscribe bridge · Windscribe controls system coverage"
	}
	if o.tun {
		coverage = "TUN inactive · local proxy listener only"
		if verdict != toneFail {
			tn := startTunnel(ctx, o.base, lport, o.verbose, t)
			defer tn.stop(t)
			if ctx.Err() != nil {
				return 0
			}
			if tn != nil {
				coverage = "TUN active · TCP path verified; helper/LAN traffic exempt, most UDP rejected; Windows DNS may leak"
			} else {
				verdict = toneWarn
			}
		} else {
			t.Line(toneWarn, "The proxy did not verify, so TUN was not started.")
		}
	}

	// 5. The result.
	title := map[tone]string{toneOK: "READY", toneWarn: "PARTLY READY", toneFail: "NOT VERIFIED"}[verdict]
	if o.mode.isWindscribe() {
		title = "WINDSCRIBE BRIDGE LISTENING; VPN NOT YET VERIFIED"
		if o.mode == ModeWindscribeAether {
			carriers, _ := proxy.ExitCounts()
			if carriers == 0 {
				title = "BRIDGE LISTENING; AETHER CARRIER NOT YET VERIFIED"
			}
		}
		if o.mode == ModeWindscribe && !proxy.HasLocalBypass() && !o.ws.enabled() {
			title = "NO LOCAL ANTI-DPI PATH AVAILABLE"
		}
	}
	pathsDesc := fmt.Sprintf("%d configured routes · adaptive selection per hostname and port", len(proxy.Stats()))
	if o.mode.exitOnly() {
		pathsDesc = "Verified foreign exits only; direct fallback blocked"
	}
	if o.mode.isWindscribe() {
		pathsDesc = fmt.Sprintf("%d local anti-DPI paths; no plain or foreign exits", len(ups))
		if o.mode == ModeWindscribeAether {
			pathsDesc = "Aether WARP only; no plain/local/Psiphon/Tor fallback"
		}
		if o.mode == ModeWindscribe && o.ws.enabled() {
			pathsDesc = o.ws.describe() + " + " + pathsDesc
		}
	}
	var lines []string
	field := func(label, value string) {
		for i, line := range wrapText(value, max(t.width()-15, 1)) {
			prefix := strings.Repeat(" ", 10)
			if i == 0 {
				prefix = t.Bold(fmt.Sprintf("%-8s", label)) + "  "
			}
			lines = append(lines, prefix+line)
		}
	}
	field("Coverage", coverage)
	field("SOCKS", "socks5://"+l.Addr().String()+t.Dim(" · remote DNS in the app"))
	field("Paths", pathsDesc)
	if httpAddr != "" {
		field("HTTP", "http://"+httpAddr+t.Dim(" · CONNECT, TCP only"))
		if o.mode.isWindscribe() {
			field("VPN", t.Yellow("Windscribe on OpenVPN TCP 443; only Windscribe can confirm the VPN connected"))
			if o.mode == ModeWindscribeAether {
				field("Carrier", "Aether WARP -> Windscribe; keep this process running; exclude ktest/aether from Windscribe VPN routes")
			}
		}
	}
	if frontNote != "" {
		field("Front", t.Dim(frontNote))
	}
	if currentExitStatus != nil {
		warpNote = currentExitStatus()
	}
	field("Exit", t.Dim(warpNote))
	field("Policy", string(o.mode))
	if !o.mode.isWindscribe() {
		field("AI", "Verified foreign exit only · blocked when unavailable")
		if len(proxied) == 0 && o.mode.exitOnly() {
			field("Checks", "deferred until a verified exit becomes available")
		} else {
			field("Checks", fmt.Sprintf("%d small site probes · refresh every 15 min after activity", len(quickcheck.Targets())))
		}
	} else {
		if o.mode == ModeWindscribeAether {
			field("AI", "SOCKS AI traffic requires verified foreign WARP; normal apps use Windscribe's VPN")
		} else {
			field("AI", "AI requests rejected by this bridge; Windscribe owns application traffic")
		}
	}
	switch {
	case o.mode.isWindscribe():
		field("Result", t.Dim("ktest watches windscribe-cli status; Windscribe owns the public IP"))
	case bypassed > 0:
		field("Result", t.Green(fmt.Sprintf("%d blocked test %s opened through ktest", bypassed, plural(bypassed, "site", "sites"))))
	case passed == len(proxied) && passed > 0:
		field("Result", "Tested sites also open directly; a bypass is not established by these checks")
	case passed == 0 && len(proxied) == 0 && o.mode.exitOnly():
		field("Result", t.Yellow("No verified upstream yet; sites were not tested"))
	case passed == 0:
		field("Result", t.Red("No tested site was reachable; run `ktest doctor` to see why"))
	}
	if frontCARelevant(o) && verdict != toneOK && fronter == nil && ctx.Err() == nil {
		// The paths that need no certificate did not reach everything. If fronting
		// would, say so now instead of leaving the user with a red result.
		fctx, fcancel := context.WithTimeout(ctx, 8*time.Second)
		var reach []string
		for _, c := range probeFronts(fctx) {
			if c.working() > 0 {
				reach = append(reach, c.family)
			}
		}
		fcancel()
		if len(reach) > 0 {
			field("Next", t.Yellow("optional website-fronting candidates observed for "+strings.Join(reach, ", ")+"; a local CA would allow HTTPS interception, not establish a VPN tunnel"))
		}
	}
	field("Stop", o.stopHint)
	t.Println("")
	t.Box(title, verdict, lines)
	t.Println("")
	if o.mode == ModeWindscribe {
		t.Println("  " + t.Dim("Windscribe connections (each new attempt rotates the carrier; only Windscribe verifies the VPN)"))
		t.Note("requested = Windscribe's target; entry = carrier address; VPN IP = Windscribe-reported exit, shown separately by CLI")
	} else {
		t.Println("  " + t.Dim("Live connections (a site is listed when its winning path is known or changes)"))
		t.Note("System route follows the current OS network, including any existing VPN. Exit IP samples are reported separately; per-site public IP is not inferred.")
	}

	// 6. Live feed until the user disconnects.
	for len(events) > 0 { // self-test traffic is already reported above
		<-events
	}
	dropped.Store(0)
	if !o.mode.isWindscribe() {
		stopRefresh := startRouteRefresh(ctx, probePort, &activity, t)
		defer stopRefresh()
	}
	feed := &siteEvents{t: t, last: map[string]string{}, failedAt: map[string]time.Time{}, verbose: o.verbose, dropped: &dropped, fronts: frontHistory}
	for {
		select {
		case <-ctx.Done():
			for len(events) > 0 {
				feed.print(<-events)
			}
			summarize(t, feed, fronter)
			return 0
		case e := <-events:
			feed.print(e)
		}
	}
}

func trimDetail(s string) string {
	runes := []rune(s)
	if len(runes) > 70 {
		return string(runes[:70]) + "…"
	}
	return s
}

// summarize prints what happened during the session.
func summarize(t *term, feed *siteEvents, fronter *front.Fronter) {
	t.Println("")
	t.Println("  " + t.Bold("Session summary"))
	ok, fail := feed.ok.Load(), feed.fail.Load()
	if n := feed.tcpOnly.Load(); n > 0 {
		t.Note("%d TCP proxy requests accepted; application/VPN negotiation unverified", n)
	}
	if n := feed.prepared.Load(); n > 0 {
		t.Note("%d fronting routes prepared; application acceptance checked separately", n)
	}
	if n := feed.rejected.Load(); n > 0 {
		t.Line(toneWarn, "%d application %s; another route preferred on retry", n, plural(int(n), "refusal", "refusals"))
	}
	if n := feed.earlyClosed.Load(); n > 0 {
		t.Note("%d connections closed before post-hello response data", n)
	}
	if ok+fail > 0 {
		t.Note("Initial responses: %d · no working route: %d", ok, fail)
	} else if feed.tcpOnly.Load() == 0 && feed.prepared.Load() == 0 {
		t.Note("No connections were made through the proxy")
	}
	var routes []*routeSelection
	selected := 0
	for _, r := range feed.routes {
		routes = append(routes, r)
		selected += r.count
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].count == routes[j].count {
			return routes[i].name < routes[j].name
		}
		return routes[i].count > routes[j].count
	})
	if selected > 0 {
		t.Note("Route setup: %s average · %s longest · %d slow (1s+) connections", shortDur(feed.setupTotal/time.Duration(selected)), shortDur(feed.setupMax), feed.slow)
	}
	for i, r := range routes {
		if i == 8 {
			break
		}
		t.Note("%s · %d selected · %s average setup", r.name, r.count, shortDur(r.setup/time.Duration(r.count)))
	}
	if feed.dropped != nil && feed.dropped.Load() > 0 {
		t.Line(toneWarn, "%d live events omitted under load; displayed counts are partial", feed.dropped.Load())
	}
	if fronter != nil {
		if feed.fronts != nil {
			for _, l := range feed.fronts.problems() {
				t.Note("%s", l)
			}
		}
		acc, ref := fronter.Stats()
		if acc+ref > 0 || fronter.Disabled() != "" {
			t.Note("fronting TLS (including startup checks): %d accepted, %d refused by applications", acc, ref)
		}
		if learned := fronter.Learned(); len(learned) > 0 {
			t.Note("fronts that worked here: %s", strings.Join(learned, "; "))
		}
	}
	t.Println("")
}

// raceDial connects to host:port (an IP literal, so no DNS) through every
// SOCKS carrier and directly at the same time, and keeps the first connection.
func raceDial(ctx context.Context, carriers []string, addr string) (net.Conn, error) {
	return raceDialPaths(ctx, carriers, addr, true)
}

func raceDialPaths(ctx context.Context, carriers []string, addr string, direct bool) (net.Conn, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type res struct {
		c   net.Conn
		err error
	}
	n := len(carriers)
	if direct {
		n++
	}
	if n == 0 {
		return nil, errors.New("no DNS carrier available")
	}
	ch := make(chan res, n)
	for _, carrier := range carriers {
		go func(carrier string) {
			c, err := smartproxy.DialVia(rctx, carrier, h, p, 5*time.Second)
			ch <- res{c, err}
		}(carrier)
	}
	if direct {
		go func() {
			c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(rctx, "tcp", addr)
			ch <- res{c, err}
		}()
	}
	var winner net.Conn
	var last error
	for i := 0; i < n; i++ {
		r := <-ch
		if r.err != nil {
			last = r.err
			continue
		}
		if winner == nil {
			winner = r.c
			cancel()
			continue
		}
		_ = r.c.Close()
	}
	if winner == nil {
		return nil, last
	}
	return winner, nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// newFronter builds the domain-fronting path when it is wanted and usable, and
// returns a one-line explanation of its state for the result box.
func newFronter(o connectOptions, resolve smartproxy.Resolver, t *term, logf func(string, ...any), history *hostAggregate) (*front.Fronter, string) {
	if o.noFront {
		return nil, "off (-no-front)"
	}
	ca, trusted := loadFrontCA()
	switch {
	case ca == nil:
		return nil, "off - optional: `ktest ca -install` lets Google, YouTube and Meta sites use domain fronting"
	case !trusted && !o.forceFront:
		return nil, "off - the system does not trust the ktest CA yet (`ktest ca -install`)"
	}
	fams := front.DefaultFamilies()
	if text, err := os.ReadFile(filepath.Join(o.base, "profiles", "fronts.txt")); err == nil {
		if extra, perr := front.ParseFronts(string(text)); perr != nil {
			t.Note("skipped profiles/fronts.txt: %v", perr)
		} else {
			fams = front.WithFronts(fams, extra)
		}
	}
	f := front.New(front.Config{
		CA: ca, Families: fams, Resolve: resolve, Logf: logf,
		OnTrouble: func(msg string) { t.Line(toneWarn, "%s", msg) },
		OnSession: func(si front.SessionInfo) {
			if history != nil && history.add(si) {
				t.Line(toneWarn, "%-26s %s", si.Host, t.Yellow("fronted connection received nothing back")+t.Dim("  via "+si.Front))
			}
		},
	})
	if missing := caMissing(ca); len(missing) > 0 {
		return f, "on, but the CA predates " + strings.Join(firstN(missing, 3), ", ") + " - run `ktest ca -renew` to cover them"
	}
	return f, "on - Google, YouTube, X, Meta, Discord and Fastly-hosted sites can use fronting / ECH"
}
