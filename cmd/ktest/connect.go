package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
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
	aiDirect            bool
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
}

func defaultConnectOptions(base string) connectOptions {
	return connectOptions{
		base: base, mode: ModeBalanced, listen: connectListenDefault, httpListen: connectHTTPDefault, strategies: 12, windscribeReconnect: true,
		ws:      wsOptions{direct: true, sni: defaultWindscribeSNIs},
		stagger: 250 * time.Millisecond, firstByte: 5 * time.Second, ready: 30 * time.Second,
		stopHint: "Press Ctrl+C to disconnect",
	}
}

// runConnect is `ktest connect`: connect now, with the defaults.
func runConnect(args []string) int {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	o := defaultConnectOptions(defaultBase())
	fs.StringVar(&o.base, "base", o.base, "portable folder holding cores/ and profiles/")
	fs.StringVar((*string)(&o.mode), "mode", string(o.mode), "balanced (AI protected), fast, windscribe, vpn (all exit-only), tor (Tor-only)")
	fs.StringVar(&o.windscribeCLI, "windscribe-cli", "", "absolute path to Windscribe desktop CLI (auto-detected on Windows)")
	fs.BoolVar(&o.windscribeReconnect, "windscribe-auto-reconnect", o.windscribeReconnect, "reconnect last selected Windscribe location after verified bootstrap becomes available")
	fs.BoolVar(&o.ws.direct, "windscribe-wstunnel", o.ws.direct, "Windscribe mode: race WStunnel and Stealth straight to the Windscribe node with chosen SNIs")
	fs.StringVar(&o.ws.sni, "windscribe-wstunnel-sni", o.ws.sni, "comma-separated TLS SNIs raced on the direct carriers")
	fs.StringVar(&o.ws.serverIP, "windscribe-wstunnel-ip", "", "Windscribe WStunnel server IP (default: the OpenVPN TCP IP minus one, as Windscribe numbers its nodes)")
	fs.StringVar(&o.ws.path, "windscribe-wstunnel-path", "", "WStunnel path (default "+wstunnel.DefaultPath+")")
	fs.StringVar(&o.ws.cdnHost, "windscribe-cdn", "", "your Cloudflare hostname whose proxied DNS record points at a Windscribe WStunnel IP; tried first")
	fs.StringVar(&o.ws.cdnSNI, "windscribe-cdn-sni", "", "TLS SNI for the CDN carrier (default: -windscribe-cdn)")
	fs.StringVar(&o.ws.cdnEdges, "windscribe-cdn-edge", "", "comma-separated CDN edge IPs (default: scan Cloudflare for edges that reach -windscribe-cdn)")
	fs.StringVar(&o.listen, "listen", o.listen, "loopback SOCKS5 address for your applications")
	fs.IntVar(&o.strategies, "strategies", o.strategies, "how many ByeDPI strategies from profiles/byedpi-strategies.txt to run (0 = none)")
	fs.BoolVar(&o.noXray, "no-xray", false, "do not run Xray profiles (including generated local TCP methods in Windscribe mode)")
	fs.BoolVar(&o.noSelf, "no-self", false, "do not add ktest's built-in ClientHello cutting paths")
	fs.BoolVar(&o.noDoH, "no-doh", false, "never use encrypted DNS (system DNS only)")
	fs.BoolVar(&o.noDirect, "no-direct", false, "do not race the plain, uncut connection")
	fs.BoolVar(&o.noFront, "no-front", false, "do not use domain fronting even if the ktest CA is trusted")
	fs.BoolVar(&o.noWarp, "no-warp", false, "do not start the WARP exit even if it is enabled")
	fs.BoolVar(&o.noHTTP, "no-http", false, "disable the local HTTP proxy for Windscribe")
	fs.StringVar(&o.httpListen, "http-listen", o.httpListen, "loopback HTTP proxy for Windscribe Proxy Settings")
	fs.StringVar(&o.exitSocks, "exit-socks", "", "optional loopback SOCKS5 exit (Tor, Psiphon or authorized Worker), TCP only")
	fs.StringVar(&o.aiExtra, "ai-extra", "", "additional AI hostnames, comma-separated; matched names require verified foreign exit")
	fs.BoolVar(&o.aiDirect, "ai-direct", false, "opt out of fail-closed protection for AI sites (real IP may be exposed)")
	fs.BoolVar(&o.tun, "tun", false, "route the whole system through ktest (Windows; asks for Administrator)")
	fs.BoolVar(&o.cert, "cert", false, "set up or renew the local certificate for domain fronting first (Windows asks you to confirm)")
	fs.BoolVar(&o.forceFront, "front", false, "use domain fronting even when the system does not report the ktest CA as trusted (Firefox with its own store)")
	fs.DurationVar(&o.stagger, "stagger", o.stagger, "head start of the first path before all others join")
	fs.DurationVar(&o.firstByte, "first-byte", o.firstByte, "how long a path may take to answer the TLS ClientHello")
	fs.DurationVar(&o.ready, "ready", o.ready, "how long to wait for each core's local port")
	fs.BoolVar(&o.verbose, "v", false, "log every path decision and core output")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: ktest connect [-v]   (all other flags are for experiments; see -h)")
		return 2
	}
	host, _, err := net.SplitHostPort(o.listen)
	if err != nil || (host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback())) {
		fmt.Fprintln(os.Stderr, "-listen must be a loopback host:port")
		return 2
	}
	mode, modeErr := parseConnectionMode(string(o.mode))
	if modeErr != nil {
		fmt.Fprintln(os.Stderr, modeErr)
		return 2
	}
	o.mode = mode
	if o.mode == ModeWindscribe && o.exitSocks != "" {
		fmt.Fprintln(os.Stderr, "Windscribe mode forbids -exit-socks: no foreign proxy/VPN exit may be used")
		return 2
	}
	if err := o.ws.validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if o.mode != ModeWindscribe && o.ws.cdnHost != "" {
		fmt.Fprintln(os.Stderr, "-windscribe-cdn only applies to -mode windscribe")
		return 2
	}
	if o.mode == ModeWindscribe && o.tun {
		fmt.Fprintln(os.Stderr, "Windscribe bootstrap cannot run with ktest -tun; stop ktest's whole-PC tunnel first")
		return 2
	}
	if o.strategies < 0 || o.strategies > 12 {
		fmt.Fprintln(os.Stderr, "-strategies must be 0..12")
		return 2
	}
	u := newTerm(os.Stdout)
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
	t        *term
	last     map[string]string
	failedAt map[string]time.Time
	ok, fail atomic.Int64
	tcpOnly  atomic.Int64
}

func (s *siteEvents) print(e smartproxy.Event) {
	t := s.t
	if e.TCPOnly {
		s.tcpOnly.Add(1)
		if isWindscribeCarrier(e.Path) {
			t.Line(toneOK, "%-26s Windscribe OpenVPN server answered via %s (%s); login is up to Windscribe", e.Host, e.Path, shortDur(e.Took))
			return
		}
		t.Line(toneInfo, "%-26s TCP proxy accepted via %s (%s); VPN handshake not verified", e.Host, e.Path, shortDur(e.Took))
		return
	}
	if e.Rejected {
		if time.Since(s.failedAt[e.Site]) >= 20*time.Second {
			s.failedAt[e.Site] = time.Now()
			reason := e.Err
			if i := strings.LastIndex(reason, "): "); i >= 0 {
				reason = reason[i+3:]
			}
			t.Line(toneWarn, "%-26s %s", e.Host, t.Yellow("the application refused the ktest certificate")+t.Dim("  "+trimDetail(reason)))
		}
		return
	}
	if e.OK {
		s.ok.Add(1)
		if s.last[e.Site] == e.Path {
			return
		}
		s.last[e.Site] = e.Path
		t.Line(toneOK, "%-26s %s %s", e.Site, t.Dim("←"), t.Bold(e.Path)+t.Dim("  "+shortDur(e.Took)))
		return
	}
	s.fail.Add(1)
	if time.Since(s.failedAt[e.Site]) < 20*time.Second {
		return
	}
	s.failedAt[e.Site] = time.Now()
	reason := e.Err
	if i := strings.LastIndex(reason, ": "); i >= 0 && len(reason) > 60 {
		reason = reason[i+2:]
	}
	t.Line(toneFail, "%-26s %s", e.Host, t.Red("no path answered")+t.Dim("  "+reason))
}

// connectSession runs until ctx ends. preflight may carry a Google DNS check
// the caller already measured.
func connectSession(ctx context.Context, o connectOptions, preflight *dnscheck.Result, t *term) int {
	t.Heading("connect", "Routing mode: "+string(o.mode))
	t.Note("%s", o.mode.message())
	if o.mode == ModeWindscribe {
		if o.exitSocks != "" {
			t.Line(toneFail, "Windscribe local-only mode forbids external SOCKS exits (-exit-socks)")
			return 2
		}
		// Mode policy is non-negotiable. Never load Aether, Psiphon, WARP,
		// Tor or foreign SOCKS, even when the user enabled them in Setup.
		o.noWarp = true
	}
	if o.mode == ModeWindscribe && o.tun {
		t.Line(toneFail, "Windscribe bootstrap cannot share ktest's system-wide TUN; run without -tun")
		return 2
	}
	if o.mode == ModeWindscribe && runtime.GOOS == "windows" {
		ifaces, _ := net.Interfaces()
		for _, iface := range ifaces {
			if strings.Contains(strings.ToLower(iface.Name), "sing-tun") && iface.Flags&net.FlagUp != 0 {
				t.Line(toneFail, "The previous ktest sing-tun is still active (%s). Stop whole-PC mode and restore Windows routes before connecting Windscribe.", iface.Name)
				return 2
			}
		}
	}
	monitor := startWindscribeMonitor(ctx, o, t)
	if monitor != nil && monitor.Connected() {
		t.Note("Windscribe already connected. ktest standing by; waiting for the official CLI to report disconnect.")
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
		t.Note("system DNS is poisoned: www.youtube.com → %s (private block-page address); a trusted resolver is used instead", ip)
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
	if !o.noXray && o.mode != ModeVPN && o.mode != ModeTor {
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
	if o.strategies > 0 && o.mode != ModeVPN && o.mode != ModeTor {
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
	if !o.noDirect && o.mode != ModeVPN && o.mode != ModeTor && o.mode != ModeWindscribe {
		ups = append(ups, smartproxy.PlainUpstreams()...)
	}
	for _, c := range up {
		ups = append(ups, smartproxy.Upstream{
			Name: c.name, Addr: fmt.Sprintf("127.0.0.1:%d", c.port),
			LocalDNS: c.localDNS, SoftResolve: strings.HasPrefix(c.name, "Xray") && !c.localBypass,
			Rank: 2, LocalBypass: o.mode == ModeWindscribe && c.localBypass,
		})
	}
	if !o.noSelf && o.mode != ModeVPN && o.mode != ModeTor {
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
			Name: "External SOCKS exit", Addr: o.exitSocks, Exit: true, AIEligible: checked == nil, Late: o.mode != ModeFast && o.mode != ModeVPN && o.mode != ModeTor, Rank: 3,
		})
	}
	if len(ups) == 0 && o.mode != ModeVPN && o.mode != ModeTor && !o.forceFront {
		t.Box("NOTHING TO RUN", toneFail, []string{"No path is available. Extract the complete portable ZIP (cores/ and profiles/)", "or run `ktest doctor`."})
		return 1
	}
	events := make(chan smartproxy.Event, 256)
	cfg := smartproxy.Config{
		Upstreams: ups, Stagger: o.stagger, FirstByteTimeout: o.firstByte,
		OnEvent: func(e smartproxy.Event) {
			select {
			case events <- e:
			default:
			}
		},
	}
	o.mode.configure(&cfg, aiRules)
	if o.mode == ModeWindscribe {
		cfg.RejectExits = true // guard both initial and dynamically added routes
		cfg.LocalOnly = true   // also reject plain/unknown relays and takeovers
	}
	if o.mode == ModeBalanced && o.aiDirect {
		cfg.ExitOnly = nil
	}
	logDNS := func(f string, a ...any) {
		if o.verbose {
			t.Printf("    %s\n", t.Dim("dns: "+fmt.Sprintf(f, a...)))
		}
	}
	var dohA, dohAAAA smartproxy.Resolver
	if !o.noDoH {
		var carriers []string
		for _, u := range ups {
			if u.Addr != "" {
				carriers = append(carriers, u.Addr)
			}
		}
		dial := func(ctx context.Context, _, addr string) (net.Conn, error) { return raceDial(ctx, carriers, addr) }
		// The public resolvers are filtered by address on many networks; the ECH
		// route to Cloudflare's resolver is not, and needs neither DNS nor a path.
		endpoints := append(append([]smartproxy.DoHEndpoint(nil), smartproxy.DefaultDoH...), echDoHEndpoint())
		dohA = smartproxy.NewDoH(endpoints, dial, nil)
		dohAAAA = smartproxy.NewDoHType(endpoints, dial, nil, "AAAA")
	}
	cfg.Resolve = smartproxy.NewTrusted(smartproxy.TrustedOptions{DoH: dohA, Logf: logDNS})
	cfg.Resolve6 = smartproxy.NewTrusted(smartproxy.TrustedOptions{DoH: dohAAAA, IPv6: true, Logf: logDNS})

	// Domain fronting is a takeover path: it needs the application to trust the
	// ktest CA, so it is only added when the system says it does.
	var fronter *front.Fronter
	frontNote := ""
	if o.mode != ModeVPN && o.mode != ModeTor && o.mode != ModeWindscribe {
		// A CDN front can act as an egress/HTTP takeover; its public-IP
		// semantics are not guaranteed. Local-only means no CDN relay.
		fronter, frontNote = newFronter(o, cfg.Resolve, t, logDNS)
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
	l, err := net.Listen("tcp", o.listen)
	if err != nil {
		t.Line(toneFail, "cannot listen on %s: %v", o.listen, err)
		return 1
	}
	monitor.attach(proxy)
	_, portText, _ := net.SplitHostPort(l.Addr().String())
	var lport int
	fmt.Sscanf(portText, "%d", &lport)
	go func() { _ = proxy.Serve(ctx, l) }()
	// Windscribe accepts an HTTP upstream proxy, while Connect speaks SOCKS5.
	// The HTTP bridge shares Connect's learned path selection without changing
	// system DNS, routing, or trust stores.
	httpAddr := ""
	if !o.noHTTP {
		var stopHTTP func()
		if o.mode == ModeWindscribe {
			dial := proxy.DialWindscribeLocal
			if o.ws.enabled() {
				logf := cfg.Logf
				if logf == nil {
					logf = func(string, ...any) {}
				}
				bridge := newWSBridge(o.ws, proxy.DialWindscribeLocal, cfg.OnEvent, logf)
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
	var stopWarp func()
	if o.mode == ModeTor {
		warpNote, stopWarp = startTor(ctx, o, proxy, t)
	} else if o.mode == ModeWindscribe {
		warpNote = "disabled: local anti-DPI only; Psiphon/Aether/WARP/Tor and foreign exits prohibited"
		stopWarp = func() {}
	} else {
		warpNote, stopWarp = startWarp(ctx, o, proxy, &dns, t, monitor)
	}
	defer stopWarp()

	// 4. Windscribe owns the network while it is connected. In that state,
	// don't run extra local website probes which could disturb its data plane.
	var proxied []quickcheck.Result
	var compared []quickcheck.Assessment
	verdict := toneInfo
	if o.mode == ModeWindscribe {
		t.Note("Windscribe mode skips unrelated website and CDN tests; only local TCP anti-DPI is permitted")
	} else if monitor == nil || !monitor.Connected() {
		vstep := t.Progress("Verifying YouTube and Google", 1)
		vctx, vcancel := context.WithTimeout(ctx, 30*time.Second)
		proxied, compared = measure(vctx, lport)
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
	} else {
		t.Note("Windscribe active: skipping extra website probes")
	}
	passed := proxiedPassCount(proxied)
	bypassed := 0
	for _, c := range compared {
		switch c.Kind {
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

	// 5. The result.
	title := map[tone]string{toneOK: "READY", toneWarn: "PARTLY READY", toneFail: "NOT VERIFIED"}[verdict]
	if o.mode == ModeWindscribe {
		title = "WINDSCRIBE BRIDGE READY; VPN NOT YET VERIFIED"
		if !proxy.HasLocalBypass() && !o.ws.enabled() {
			title = "NO LOCAL ANTI-DPI PATH AVAILABLE"
		}
	}
	pathsDesc := fmt.Sprintf("%d racing: plain, %d external, %d built-in", len(ups), len(up), len(ups)-len(up)-countPlain(ups)) + frontSuffix(fronter)
	if o.mode == ModeWindscribe {
		pathsDesc = fmt.Sprintf("%d local anti-DPI paths; no plain or foreign exits", len(ups))
		if o.ws.enabled() {
			pathsDesc = o.ws.describe() + " + " + pathsDesc
		}
	}
	lines := []string{
		t.Bold("Proxy   ") + "  socks5://" + l.Addr().String() + t.Dim("   (turn on \"proxy DNS\" / remote DNS in the app)"),
		t.Bold("Paths   ") + "  " + pathsDesc,
	}
	if httpAddr != "" {
		lines = append(lines, t.Bold("HTTP    ")+"  http://"+httpAddr+t.Dim("   (Windscribe Proxy Settings; TCP only)"))
		if o.mode == ModeWindscribe {
			lines = append(lines, t.Bold("VPN     ")+"  "+t.Yellow("Windscribe on OpenVPN TCP 443; only Windscribe can confirm the VPN connected"))
		}
	}
	if frontNote != "" {
		lines = append(lines, t.Bold("Front   ")+"  "+t.Dim(frontNote))
	}
	lines = append(lines, t.Bold("Exit    ")+"  "+t.Dim(warpNote))
	lines = append(lines, t.Bold("Mode    ")+"  "+t.Dim(o.mode.message()))
	switch {
	case o.mode == ModeWindscribe:
		lines = append(lines, t.Bold("Result  ")+"  "+t.Dim("ktest watches windscribe-cli status; Windscribe owns the public IP"))
	case bypassed > 0:
		lines = append(lines, t.Bold("Result  ")+"  "+t.Green(fmt.Sprintf("%d site(s) blocked on this network are open through ktest", bypassed)))
	case passed == len(proxied) && passed > 0:
		lines = append(lines, t.Bold("Result  ")+"  "+"everything tested is also open directly; if another VPN is on, turn it off to see a bypass")
	case passed == 0:
		lines = append(lines, t.Bold("Result  ")+"  "+t.Red("no tested site was reachable; run `ktest doctor` to see why"))
	}
	if o.mode != ModeWindscribe && verdict != toneOK && fronter == nil && !o.noFront && ctx.Err() == nil {
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
			lines = append(lines, t.Bold("Next    ")+"  "+t.Yellow("domain fronting reaches "+strings.Join(reach, ", ")+" here: run `ktest ca -install`, then Connect again"))
		}
	}
	lines = append(lines, t.Bold("Stop    ")+"  "+o.stopHint)
	t.Println("")
	t.Box(title, verdict, lines)
	t.Println("")
	if o.mode == ModeWindscribe {
		t.Println("  " + t.Dim("Windscribe connections (each new attempt rotates the carrier; only Windscribe verifies the VPN)"))
	} else {
		t.Println("  " + t.Dim("Live connections (a site is listed when its winning path is known or changes)"))
	}

	// 5b. The system-wide tunnel, once the proxy has proven itself.
	if o.tun && verdict != toneFail {
		t.Println("")
		tn := startTunnel(ctx, o.base, lport, o.verbose, t)
		defer tn.stop(t)
		if tn != nil {
			t.Line(toneOK, "System-wide: every application on this PC now goes through ktest %s", t.Dim("(TCP; UDP is dropped so applications fall back to TCP)"))
		}
		t.Println("")
	} else if o.tun {
		t.Line(toneWarn, "The proxy did not verify, so the system-wide tunnel was not started.")
	}

	// 6. Live feed until the user disconnects.
	for len(events) > 0 { // self-test traffic is already reported above
		<-events
	}
	feed := &siteEvents{t: t, last: map[string]string{}, failedAt: map[string]time.Time{}}
	for {
		select {
		case <-ctx.Done():
			summarize(t, proxy, feed, fronter)
			return 0
		case e := <-events:
			feed.print(e)
		}
	}
}

func countPlain(ups []smartproxy.Upstream) int {
	n := 0
	for _, u := range ups {
		if strings.HasPrefix(u.Name, "plain") {
			n++
		}
	}
	return n
}

func trimDetail(s string) string {
	if len(s) > 70 {
		return s[:70] + "…"
	}
	return s
}

// summarize prints what happened during the session.
func summarize(t *term, proxy *smartproxy.Proxy, feed *siteEvents, fronter *front.Fronter) {
	t.Println("")
	t.Println("  " + t.Bold("Session summary"))
	ok, fail := feed.ok.Load(), feed.fail.Load()
	if n := feed.tcpOnly.Load(); n > 0 {
		t.Printf("    %d TCP proxy requests accepted; destination/application/VPN negotiation not verified by these counts\n", n)
	}
	if total := ok + fail; total > 0 {
		pct := float64(ok) / float64(total)
		k := toneOK
		if pct < 0.9 {
			k = toneWarn
		}
		if pct < 0.5 {
			k = toneFail
		}
		t.Printf("    %s %3d%%  %d of %d connections answered\n", t.Bar(pct, 20, k), int(pct*100+0.5), ok, total)
	} else if feed.tcpOnly.Load() == 0 {
		t.Println("    " + t.Dim("no connections were made through the proxy"))
	}
	stats := proxy.Stats()
	maxWins := 0
	for _, s := range stats {
		maxWins = max(maxWins, s.Wins)
	}
	shown := 0
	for _, s := range stats {
		if s.Wins == 0 || shown == 8 {
			continue
		}
		shown++
		t.Printf("    %s %-44s %s\n", t.Bar(float64(s.Wins)/float64(maxWins), 12, toneInfo), s.Name, t.Dim(fmt.Sprintf("%d %s · %d ms avg", s.Wins, plural(s.Wins, "win", "wins"), s.AvgMS)))
	}
	if fronter != nil {
		for _, l := range frontHosts.problems() {
			t.Println("    " + t.Dim(l))
		}
		acc, ref := fronter.Stats()
		if acc+ref > 0 || fronter.Disabled() != "" {
			t.Printf("    %s\n", t.Dim(fmt.Sprintf("domain fronting: %d accepted, %d refused by applications", acc, ref)))
		}
		if learned := fronter.Learned(); len(learned) > 0 {
			t.Printf("    %s\n", t.Dim("fronts that worked here: "+strings.Join(learned, "; ")))
		}
	}
	t.Println("")
}

// raceDial connects to host:port (an IP literal, so no DNS) through every
// SOCKS carrier and directly at the same time, and keeps the first connection.
func raceDial(ctx context.Context, carriers []string, addr string) (net.Conn, error) {
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
	n := len(carriers) + 1
	ch := make(chan res, n)
	for _, carrier := range carriers {
		go func(carrier string) {
			c, err := smartproxy.DialVia(rctx, carrier, h, p, 5*time.Second)
			ch <- res{c, err}
		}(carrier)
	}
	go func() {
		c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(rctx, "tcp", addr)
		ch <- res{c, err}
	}()
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
func newFronter(o connectOptions, resolve smartproxy.Resolver, t *term, logf func(string, ...any)) (*front.Fronter, string) {
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
			if frontHosts.add(si) {
				t.Line(toneWarn, "%-26s %s", si.Host, t.Yellow("fronted connection received nothing back")+t.Dim("  via "+si.Front))
			}
		},
	})
	if missing := caMissing(ca); len(missing) > 0 {
		return f, "on, but the CA predates " + strings.Join(firstN(missing, 3), ", ") + " - run `ktest ca -renew` to cover them"
	}
	return f, "on - Google, YouTube, X, Meta, Discord and Fastly-hosted sites can use fronting / ECH"
}

func frontSuffix(f *front.Fronter) string {
	if f == nil {
		return ""
	}
	return " + domain fronting"
}
