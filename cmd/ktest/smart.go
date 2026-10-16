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
	"sync"
	"syscall"
	"time"

	"github.com/Nishef1/ktest/internal/dnscheck"
	"github.com/Nishef1/ktest/internal/quickcheck"
	"github.com/Nishef1/ktest/internal/revive"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

const (
	smartListenDefault = "127.0.0.1:10800"
	smartPort          = 10800
	smartXrayBPort     = xrayPort // 10808
	smartXrayAPort     = 10811
	smartByeDPIBase    = 10812
)

// smartCore is one upstream core run side by side with the others.
type smartCore struct {
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

// smartOptions configures one smart session (CLI or menu).
type smartOptions struct {
	base       string
	listen     string
	strategies int
	noXray     bool
	noSelf     bool
	noDoH      bool
	noDirect   bool
	stagger    time.Duration
	firstByte  time.Duration
	ready      time.Duration
	verbose    bool
	noSelfTest bool // the menu runs its own website check
}

func defaultSmartOptions(base string) smartOptions {
	return smartOptions{
		base: base, listen: smartListenDefault, strategies: 12,
		stagger: 300 * time.Millisecond, firstByte: 5 * time.Second, ready: 30 * time.Second,
	}
}

// runSmart starts several different cores at once and puts one local SOCKS5
// listener in front of them that races the paths for every TLS connection.
func runSmart(args []string) int {
	fs := flag.NewFlagSet("smart", flag.ContinueOnError)
	o := defaultSmartOptions(defaultBase())
	fs.StringVar(&o.base, "base", o.base, "portable folder holding cores/ and profiles/")
	fs.StringVar(&o.listen, "listen", o.listen, "loopback SOCKS5 address for your applications")
	fs.IntVar(&o.strategies, "strategies", o.strategies, "how many ByeDPI strategies from profiles/byedpi-strategies.txt to run side by side, in file order (0 = none)")
	fs.BoolVar(&o.noXray, "no-xray", false, "do not run the two Xray profiles")
	fs.BoolVar(&o.noSelf, "no-self", false, "do not add ktest's built-in ClientHello cutting paths")
	fs.BoolVar(&o.noDoH, "no-doh", false, "let ByeDPI paths use the system DNS (poisoned on many filtered networks)")
	fs.BoolVar(&o.noDirect, "no-direct", false, "do not race the plain, uncut connection (the baseline for sites that are not blocked)")
	fs.DurationVar(&o.stagger, "stagger", o.stagger, "head start of the best-known path before the next one joins")
	fs.DurationVar(&o.firstByte, "first-byte", o.firstByte, "how long a path may take to answer the TLS ClientHello")
	fs.DurationVar(&o.ready, "ready", coreReadyLimit, "how long to wait for each core's local port")
	fs.BoolVar(&o.verbose, "v", false, "log every path decision")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: ktest smart [-listen 127.0.0.1:10800] [-strategies 3] [-no-xray] [-direct] [-v]")
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
	return smartSession(ctx, o, nil, os.Stdout)
}

// smartSession runs until ctx ends. dns may carry a preflight already measured
// by the caller.
func smartSession(ctx context.Context, o smartOptions, dnsResult *dnscheck.Result, out io.Writer) int {
	var cores []*smartCore
	add := func(name string, port int, localDNS bool, mk func(io.Writer) (launcher, error)) {
		c := &smartCore{name: name, port: port, logs: &tailBuffer{max: 4096}, localDNS: localDNS}
		if o.verbose {
			c.logs.tee = out
		}
		l, err := mk(c.logs)
		if err != nil {
			fmt.Fprintf(out, "SKIP  %-28s %v\n", name, err)
			return
		}
		c.launch = l
		cores = append(cores, c)
	}
	if !o.noXray {
		for _, x := range []struct {
			variant string
			port    int
		}{{"B", smartXrayBPort}, {"A", smartXrayAPort}} {
			x := x
			add("Xray "+x.variant, x.port, false, func(w io.Writer) (launcher, error) { return xrayLauncher(o.base, x.variant, x.port, w) })
		}
	}
	if o.strategies > 0 {
		bin := byeDPIBinary(o.base)
		list, source, err := loadStrategies(o.base)
		switch {
		case !fileOK(bin):
			fmt.Fprintf(out, "SKIP  ByeDPI: missing %s\n", bin)
		case err != nil:
			fmt.Fprintf(out, "SKIP  ByeDPI strategies: %v\n", err)
		default:
			if len(list) > o.strategies {
				list = list[:o.strategies]
			}
			fmt.Fprintf(out, "ByeDPI strategies from %s (first %d)\n", source, len(list))
			for i, s := range list {
				s, port := s, smartByeDPIBase+i
				add("ByeDPI "+s.Label, port, true, func(w io.Writer) (launcher, error) { return byeDPILauncher(bin, port, s.Args, w), nil })
			}
		}
	}
	if len(cores) == 0 && o.noSelf {
		fmt.Fprintln(out, "nothing to run; extract the complete portable ZIP (cores/ and profiles/)")
		return 1
	}

	var dns dnscheck.Result
	if dnsResult != nil {
		dns = *dnsResult
	} else {
		dns = dnscheck.CheckGoogleDNS(ctx)
		fmt.Fprintln(out, "DNS preflight:", dns.Format())
	}

	var live []*smartCore
	for _, c := range cores {
		if err := portFree(c.port); err != nil {
			fmt.Fprintf(out, "SKIP  %-28s %v\n", c.name, err)
			continue
		}
		cctx, cancel := context.WithCancel(ctx)
		rc := &runningCore{cancel: cancel, done: make(chan struct{})}
		c.run = rc
		go func(c *smartCore) {
			rc.err = c.launch(cctx, &dns)
			close(rc.done)
		}(c)
		live = append(live, c)
	}
	defer func() {
		for _, c := range live {
			c.run.stop()
		}
	}()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var up []*smartCore
	for _, c := range live {
		wg.Add(1)
		go func(c *smartCore) {
			defer wg.Done()
			if waitForPort(ctx, c.run.done, c.port, o.ready) {
				mu.Lock()
				up = append(up, c)
				mu.Unlock()
				fmt.Fprintf(out, "UP    %-28s 127.0.0.1:%d\n", c.name, c.port)
				return
			}
			note := "port did not open"
			select {
			case <-c.run.done:
				if c.run.err != nil {
					note = c.run.err.Error()
				}
			default:
				if l := c.logs.lastLine(); l != "" {
					note += "; last core output: " + l
				}
			}
			fmt.Fprintf(out, "FAIL  %-28s %s\n", c.name, note)
		}(c)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return 0
	}
	if len(up) == 0 && o.noSelf {
		fmt.Fprintln(out, "No upstream core started; run `ktest doctor`.")
		return 1
	}
	sort.Slice(up, func(i, j int) bool { return up[i].port < up[j].port })

	// Initial order = initial head start: the uncut baseline first, so sites
	// that are not blocked never pay for a cut ClientHello; learned wins reorder
	// this per site afterwards.
	var ups []smartproxy.Upstream
	if !o.noDirect {
		ups = append(ups, smartproxy.PlainUpstreams()...)
	}
	for _, c := range up {
		ups = append(ups, smartproxy.Upstream{Name: c.name, Addr: fmt.Sprintf("127.0.0.1:%d", c.port), LocalDNS: c.localDNS})
	}
	if !o.noSelf {
		ups = append(ups, smartproxy.DesyncUpstreams()...)
	}
	cfg := smartproxy.Config{Upstreams: ups, Stagger: o.stagger, FirstByteTimeout: o.firstByte}
	// Name resolution is the first thing a censor poisons, so it is never left
	// to the system resolver alone: system answers are screened for private
	// block-page addresses, then encrypted DNS is asked by IP literal (no DNS
	// needed to find the resolver) over every working path at once, then the
	// Google front-end address stands in for Google-owned names.
	var dohA, dohAAAA smartproxy.Resolver
	if !o.noDoH {
		var carriers []string
		for _, u := range ups {
			if u.Addr != "" {
				carriers = append(carriers, u.Addr)
			}
		}
		dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
			return raceDial(ctx, carriers, addr)
		}
		dohA = smartproxy.NewDoH(smartproxy.DefaultDoH, dial, nil)
		dohAAAA = smartproxy.NewDoHType(smartproxy.DefaultDoH, dial, nil, "AAAA")
	}
	logDNS := func(f string, a ...any) {
		if o.verbose {
			fmt.Fprintf(out, "  dns: "+f+"\n", a...)
		}
	}
	cfg.Resolve = smartproxy.NewTrusted(smartproxy.TrustedOptions{DoH: dohA, Logf: logDNS})
	cfg.Resolve6 = smartproxy.NewTrusted(smartproxy.TrustedOptions{DoH: dohAAAA, IPv6: true, Logf: logDNS})
	if o.verbose {
		cfg.Logf = func(f string, a ...any) { fmt.Fprintf(out, "  "+f+"\n", a...) }
	}
	proxy, err := smartproxy.New(cfg)
	if err != nil {
		fmt.Fprintln(out, err)
		return 2
	}
	l, err := net.Listen("tcp", o.listen)
	if err != nil {
		fmt.Fprintln(out, "listen:", err)
		return 1
	}
	_, portText, _ := net.SplitHostPort(l.Addr().String())
	var lport int
	fmt.Sscanf(portText, "%d", &lport)
	go func() { _ = proxy.Serve(ctx, l) }()

	fmt.Fprintf(out, "\nSMART SOCKS5 proxy on %s racing %d path(s). Point applications here (enable remote/proxy DNS).\n", l.Addr(), len(ups))
	fmt.Fprintln(out, "No system proxy, DNS or route was changed. Ctrl+C stops everything.")
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	if o.noSelfTest {
		cancel()
		checkCtx, cancel = ctx, func() {}
	}
	for _, r := range selfTest(checkCtx, lport, o.noSelfTest) {
		state := "FAIL"
		if r.Success {
			state = "OK  "
		}
		fmt.Fprintf(out, "SELFTEST %s %-8s via the smart proxy: %s\n", state, r.Target, r.Detail)
	}
	cancel()

	<-ctx.Done()
	fmt.Fprintln(out, "\nStopping. Results of this session:")
	for _, s := range proxy.Stats() {
		fmt.Fprintf(out, "  %-34s wins=%-4d failures=%-4d avg=%dms\n", s.Name, s.Wins, s.Failures, s.AvgMS)
	}
	winners := proxy.Winners()
	hosts := make([]string, 0, len(winners))
	for h := range winners {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	if len(hosts) > 0 {
		fmt.Fprintln(out, "Path that last worked per site (kept in memory only, never written to disk):")
		for _, h := range hosts {
			fmt.Fprintf(out, "  %-40s %s\n", h, winners[h])
		}
	}
	return 0
}

// selfTest checks YouTube and Google through the smart port unless the caller
// already runs its own website check.
func selfTest(ctx context.Context, port int, skip bool) []quickcheck.Result {
	if skip {
		return nil
	}
	return quickcheck.Run(ctx, port, 10*time.Second)
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
