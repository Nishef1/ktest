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

// runSmart starts several different cores at once and puts one local SOCKS5
// listener in front of them that races the paths for every TLS connection.
func runSmart(args []string) int {
	fs := flag.NewFlagSet("smart", flag.ContinueOnError)
	exe, _ := os.Executable()
	base := fs.String("base", filepath.Dir(exe), "portable folder holding cores/ and profiles/")
	listen := fs.String("listen", smartListenDefault, "loopback SOCKS5 address for your applications")
	strategies := fs.Int("strategies", 3, "how many ByeDPI strategies from profiles/byedpi-strategies.txt to run (0 = none)")
	noXray := fs.Bool("no-xray", false, "do not run the two Xray profiles")
	noSelf := fs.Bool("no-self", false, "do not add ktest's built-in ClientHello cutting paths")
	noDoH := fs.Bool("no-doh", false, "let ByeDPI paths use the system DNS (poisoned on many filtered networks)")
	direct := fs.Bool("direct", false, "also race the ordinary system route (uses local DNS)")
	stagger := fs.Duration("stagger", 300*time.Millisecond, "head start of the best-known path before the next one joins")
	firstByte := fs.Duration("first-byte", 5*time.Second, "how long a path may take to answer the TLS ClientHello")
	ready := fs.Duration("ready", coreReadyLimit, "how long to wait for each core's local port")
	verbose := fs.Bool("v", false, "log every path decision")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: ktest smart [-listen 127.0.0.1:10800] [-strategies 3] [-no-xray] [-direct] [-v]")
		return 2
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || (host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback())) {
		fmt.Fprintln(os.Stderr, "-listen must be a loopback host:port")
		return 2
	}
	if *strategies < 0 || *strategies > 8 {
		fmt.Fprintln(os.Stderr, "-strategies must be 0..8")
		return 2
	}
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	var cores []*smartCore
	add := func(name string, port int, localDNS bool, mk func(io.Writer) (launcher, error)) {
		c := &smartCore{name: name, port: port, logs: &tailBuffer{max: 4096}, localDNS: localDNS}
		if *verbose {
			c.logs.tee = os.Stderr
		}
		l, err := mk(c.logs)
		if err != nil {
			fmt.Printf("SKIP  %-28s %v\n", name, err)
			return
		}
		c.launch = l
		cores = append(cores, c)
	}
	if !*noXray {
		for _, x := range []struct {
			variant string
			port    int
		}{{"B", smartXrayBPort}, {"A", smartXrayAPort}} {
			x := x
			add("Xray "+x.variant, x.port, false, func(w io.Writer) (launcher, error) { return xrayLauncher(*base, x.variant, x.port, w) })
		}
	}
	if *strategies > 0 {
		bin := byeDPIBinary(*base)
		list, source, err := loadStrategies(*base)
		switch {
		case !fileOK(bin):
			fmt.Printf("SKIP  ByeDPI: missing %s\n", bin)
		case err != nil:
			fmt.Printf("SKIP  ByeDPI strategies: %v\n", err)
		default:
			if len(list) > *strategies {
				list = list[:*strategies]
			}
			fmt.Printf("ByeDPI strategies from %s (first %d)\n", source, len(list))
			for i, s := range list {
				s, port := s, smartByeDPIBase+i
				add("ByeDPI "+s.Label, port, true, func(w io.Writer) (launcher, error) { return byeDPILauncher(bin, port, s.Args, w), nil })
			}
		}
	}
	if len(cores) == 0 && *noSelf {
		fmt.Fprintln(os.Stderr, "nothing to run; extract the complete portable ZIP (cores/ and profiles/)")
		return 1
	}

	dns := dnscheck.CheckGoogleDNS(ctx)
	fmt.Println("DNS preflight:", dns.Format())

	var live []*smartCore
	for _, c := range cores {
		if err := portFree(c.port); err != nil {
			fmt.Printf("SKIP  %-28s %v\n", c.name, err)
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
			if waitForPort(ctx, c.run.done, c.port, *ready) {
				mu.Lock()
				up = append(up, c)
				mu.Unlock()
				fmt.Printf("UP    %-28s 127.0.0.1:%d\n", c.name, c.port)
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
			fmt.Printf("FAIL  %-28s %s\n", c.name, note)
		}(c)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return 0
	}
	if len(up) == 0 && *noSelf {
		fmt.Println("No upstream core started; run `ktest doctor`.")
		return 1
	}
	sort.Slice(up, func(i, j int) bool { return up[i].port < up[j].port })

	var ups []smartproxy.Upstream
	for _, c := range up {
		ups = append(ups, smartproxy.Upstream{Name: c.name, Addr: fmt.Sprintf("127.0.0.1:%d", c.port), LocalDNS: c.localDNS})
	}
	if !*noSelf {
		ups = append(ups, smartproxy.DesyncUpstreams()...)
	}
	if *direct {
		ups = append(ups, smartproxy.Upstream{Name: "direct (system route)", LocalDNS: true})
	}
	cfg := smartproxy.Config{Upstreams: ups, Stagger: *stagger, FirstByteTimeout: *firstByte}
	if !*noDoH {
		// Encrypted DNS for upstreams that would otherwise use the system
		// resolver. The DoH requests travel over a name-resolving upstream
		// (Xray) when one is up, else over the system route.
		var carriers []string
		for _, u := range ups {
			if !u.LocalDNS {
				carriers = append(carriers, u.Addr)
			}
		}
		dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
			h, p, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			for _, carrier := range carriers {
				if c, err := smartproxy.DialVia(ctx, carrier, h, p, 6*time.Second); err == nil {
					return c, nil
				}
			}
			return (&net.Dialer{Timeout: 6 * time.Second}).DialContext(ctx, "tcp", addr)
		}
		cfg.Resolve = smartproxy.NewDoH(smartproxy.DefaultDoH, dial, nil)
	}
	if *verbose {
		cfg.Logf = func(f string, a ...any) { fmt.Printf("  "+f+"\n", a...) }
	}
	proxy, err := smartproxy.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		return 1
	}
	_, portText, _ := net.SplitHostPort(l.Addr().String())
	var lport int
	fmt.Sscanf(portText, "%d", &lport)
	go func() { _ = proxy.Serve(ctx, l) }()

	fmt.Printf("\nSMART SOCKS5 proxy on %s racing %d path(s). Point applications here (enable remote/proxy DNS).\n", l.Addr(), len(ups))
	fmt.Println("No system proxy, DNS or route was changed. Ctrl+C stops everything.")
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	for _, r := range quickcheck.Run(checkCtx, lport, 10*time.Second) {
		state := "FAIL"
		if r.Success {
			state = "OK  "
		}
		fmt.Printf("SELFTEST %s %-8s via the smart proxy: %s\n", state, r.Target, r.Detail)
	}
	cancel()

	<-ctx.Done()
	fmt.Println("\nStopping. Results of this session:")
	for _, s := range proxy.Stats() {
		fmt.Printf("  %-34s wins=%-4d failures=%-4d avg=%dms\n", s.Name, s.Wins, s.Failures, s.AvgMS)
	}
	winners := proxy.Winners()
	hosts := make([]string, 0, len(winners))
	for h := range winners {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	if len(hosts) > 0 {
		fmt.Println("Path that last worked per site (kept in memory only, never written to disk):")
		for _, h := range hosts {
			fmt.Printf("  %-40s %s\n", h, winners[h])
		}
	}
	return 0
}
