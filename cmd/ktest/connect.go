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
	"github.com/Nishef1/ktest/internal/front"
	"github.com/Nishef1/ktest/internal/revive"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

const (
	connectListenDefault = "127.0.0.1:10800"
	connectPort          = 10800
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
	localDNS bool
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

// connectOptions configures one connect session (CLI or menu). The defaults are
// the product; every field is for experiments.
type connectOptions struct {
	base       string
	listen     string
	strategies int
	noXray     bool
	noSelf     bool
	noDoH      bool
	noDirect   bool
	noFront    bool
	forceFront bool
	stagger    time.Duration
	firstByte  time.Duration
	ready      time.Duration
	verbose    bool
	stopHint   string
}

func defaultConnectOptions(base string) connectOptions {
	return connectOptions{
		base: base, listen: connectListenDefault, strategies: 12,
		stagger: 250 * time.Millisecond, firstByte: 5 * time.Second, ready: 30 * time.Second,
		stopHint: "Press Ctrl+C to disconnect",
	}
}

// runConnect is `ktest connect`: connect now, with the defaults.
func runConnect(args []string) int {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	o := defaultConnectOptions(defaultBase())
	fs.StringVar(&o.base, "base", o.base, "portable folder holding cores/ and profiles/")
	fs.StringVar(&o.listen, "listen", o.listen, "loopback SOCKS5 address for your applications")
	fs.IntVar(&o.strategies, "strategies", o.strategies, "how many ByeDPI strategies from profiles/byedpi-strategies.txt to run (0 = none)")
	fs.BoolVar(&o.noXray, "no-xray", false, "do not run the two Xray profiles")
	fs.BoolVar(&o.noSelf, "no-self", false, "do not add ktest's built-in ClientHello cutting paths")
	fs.BoolVar(&o.noDoH, "no-doh", false, "never use encrypted DNS (system DNS only)")
	fs.BoolVar(&o.noDirect, "no-direct", false, "do not race the plain, uncut connection")
	fs.BoolVar(&o.noFront, "no-front", false, "do not use domain fronting even if the ktest CA is trusted")
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
	if o.strategies < 0 || o.strategies > 12 {
		fmt.Fprintln(os.Stderr, "-strategies must be 0..12")
		return 2
	}
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	return connectSession(ctx, o, nil, newTerm(os.Stdout))
}

// siteEvents prints the live feed: one line per site when its winning path is
// first known or changes, and at most one failure line per site every 20 s.
type siteEvents struct {
	t        *term
	last     map[string]string
	failedAt map[string]time.Time
	ok, fail atomic.Int64
}

func (s *siteEvents) print(e smartproxy.Event) {
	t := s.t
	if e.Rejected {
		if time.Since(s.failedAt[e.Site]) >= 20*time.Second {
			s.failedAt[e.Site] = time.Now()
			t.Line(toneWarn, "%-26s %s", e.Host, t.Yellow("the application refused the ktest certificate")+t.Dim("  (is the CA trusted in that application?)"))
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
	t.Heading("connect", "Races every method for each connection. No system proxy, DNS or route is changed.")

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
	add := func(name string, port int, localDNS bool, mk func(io.Writer) (launcher, error)) {
		c := &pathCore{name: name, port: port, logs: &tailBuffer{max: 4096}, localDNS: localDNS}
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
	if !o.noXray {
		for _, x := range []struct {
			variant string
			port    int
		}{{"B", connectXrayBPort}, {"A", connectXrayAPort}} {
			x := x
			add("Xray fragment "+x.variant, x.port, true, func(w io.Writer) (launcher, error) { return xrayLauncher(o.base, x.variant, x.port, w) })
		}
	}
	if o.strategies > 0 {
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
				add("ByeDPI "+s.Label, port, true, func(w io.Writer) (launcher, error) { return byeDPILauncher(bin, port, s.Args, w), nil })
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
		prog := t.Progress("Starting external paths", len(live))
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
	if !o.noDirect {
		ups = append(ups, smartproxy.PlainUpstreams()...)
	}
	for _, c := range up {
		ups = append(ups, smartproxy.Upstream{Name: c.name, Addr: fmt.Sprintf("127.0.0.1:%d", c.port), LocalDNS: c.localDNS, SoftResolve: strings.HasPrefix(c.name, "Xray"), Rank: 2})
	}
	if !o.noSelf {
		ups = append(ups, smartproxy.DesyncUpstreams()...)
	}
	if len(ups) == 0 && !o.forceFront {
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
		dohA = smartproxy.NewDoH(smartproxy.DefaultDoH, dial, nil)
		dohAAAA = smartproxy.NewDoHType(smartproxy.DefaultDoH, dial, nil, "AAAA")
	}
	cfg.Resolve = smartproxy.NewTrusted(smartproxy.TrustedOptions{DoH: dohA, Logf: logDNS})
	cfg.Resolve6 = smartproxy.NewTrusted(smartproxy.TrustedOptions{DoH: dohAAAA, IPv6: true, Logf: logDNS})

	// Domain fronting is a takeover path: it needs the application to trust the
	// ktest CA, so it is only added when the system says it does.
	fronter, frontNote := newFronter(o, cfg.Resolve, t, logDNS)
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
	_, portText, _ := net.SplitHostPort(l.Addr().String())
	var lport int
	fmt.Sscanf(portText, "%d", &lport)
	go func() { _ = proxy.Serve(ctx, l) }()

	// 4. Verify through the proxy, against the plain route.
	vstep := t.Progress("Verifying YouTube and Google", 1)
	vctx, vcancel := context.WithTimeout(ctx, 30*time.Second)
	proxied, compared := measure(vctx, lport)
	vcancel()
	if ctx.Err() != nil {
		return 0
	}
	passed := proxiedPassCount(proxied)
	verdict := toneOK
	switch {
	case passed == 0:
		verdict = toneFail
	case passed < len(proxied):
		verdict = toneWarn
	}
	vstep.Finish(verdict, fmt.Sprintf("%d of %d reachable through ktest", passed, len(proxied)))
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
	lines := []string{
		t.Bold("Proxy   ") + "  socks5://" + l.Addr().String() + t.Dim("   (turn on \"proxy DNS\" / remote DNS in the app)"),
		t.Bold("Paths   ") + fmt.Sprintf("  %d racing: plain, %d external, %d built-in", len(ups), len(up), len(ups)-len(up)-countPlain(ups)) + frontSuffix(fronter),
	}
	if frontNote != "" {
		lines = append(lines, t.Bold("Front   ")+"  "+t.Dim(frontNote))
	}
	switch {
	case bypassed > 0:
		lines = append(lines, t.Bold("Result  ")+"  "+t.Green(fmt.Sprintf("%d site(s) blocked on this network are open through ktest", bypassed)))
	case passed == len(proxied) && passed > 0:
		lines = append(lines, t.Bold("Result  ")+"  "+"everything tested is also open directly; if another VPN is on, turn it off to see a bypass")
	case passed == 0:
		lines = append(lines, t.Bold("Result  ")+"  "+t.Red("no tested site was reachable; run `ktest doctor` to see why"))
	}
	if verdict != toneOK && fronter == nil && !o.noFront && ctx.Err() == nil {
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
	t.Println("  " + t.Dim("Live connections (a site is listed when its winning path is known or changes)"))

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
	} else {
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
