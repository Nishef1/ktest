package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Nishef1/ktest/internal/access"
	"github.com/Nishef1/ktest/internal/cdnranges"
	"github.com/Nishef1/ktest/internal/dnscheck"
	"github.com/Nishef1/ktest/internal/edges"
	"github.com/Nishef1/ktest/internal/experiment"
	"github.com/Nishef1/ktest/internal/pathdiag"
	"github.com/Nishef1/ktest/internal/probe"
	"github.com/Nishef1/ktest/internal/proofserver"
	"github.com/Nishef1/ktest/internal/revive"
	"github.com/Nishef1/ktest/internal/systemtun"
)

func main() {
	killChildrenOnExit()
	exitWithGoRun()
	code := run(os.Args[1:])
	reapTracked() // the kill-on-close job is not guaranteed; never leave a core behind
	os.Exit(code)
}

const usageText = `ktest: free access toolkit

  ktest                    menu
  ktest connect            connect with saved choices (initial policy: Balanced)
    -mode fast             faster ordinary-site routing; AI requires a foreign exit
    -mode aether           Aether WARP/Psiphon search; verified foreign exit
    -mode psiphon          Aether to Psiphon; Psiphon profiles only
    -mode tor              Aether to Tor; Tor circuit only
    -mode windscribe       carry the Windscribe app (OpenVPN TCP over WStunnel)
    -mode windscribe-aether carry Windscribe OpenVPN TCP through Aether WARP
    -aether-method auto    choose by saved network measurements; see connect -h
    -tun                   Whole PC TCP (initial Windows default; Administrator)
    -tun=false             Proxy coverage; remember it for the next launch
    -v                     log every decision (ktest connect -h lists every flag)
  ktest doctor             diagnose this network and the package; changes nothing
    -mode windscribe       Windscribe-specific prerequisites/status; no reconnects
  ktest windscribe-test    fixed-entry SNI comparison (-target location-or-TCP-IP)
    -zapret fake|split|combo opt-in Windows single-entry packet desync A/B (Administrator)
    -verify-vpn            CLI + one system HTTPS exit-IP check; no reconnects
  ktest aether-test        bounded per-network comparison (-budget 3m; optional -speed)

Setup
  ktest ca                 domain-fronting certificate (-install, -renew, -uninstall, -delete)
  ktest warp               WARP/Psiphon exit for Telegram and sites blocked by address
  ktest strategies         list or write the editable ByeDPI strategy file

Tools and experiments (see docs/)
  ktest ranges             complete CDN address inventory (-update refreshes it)
  ktest scan               provider HTTPS reachability (-provider cloudflare|akamai|google|fastly|meta|cloudfront|gcore)
    -windscribe-cdn HOST   test WebSocket routing to your own CDN hostname/origin
  ktest path               DNS / TCP / TLS stage diagnosis of one URL
  ktest revive             run one Xray profile on its own
  ktest access             domain-scoped proxy backed by SNI-Spoofing-Go
  ktest probe | compare | edges | echo    controlled-origin experiments
`

func run(args []string) int {
	// Internal schema-check export: no networking or core startup.
	if (len(args) == 4 || len(args) == 5) && args[0] == "profile-preview" && args[1] == "-profile" {
		input, err := os.ReadFile(args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		dnsMode := ""
		if len(args) == 5 {
			if args[4] != "udp" && args[4] != "tcp" {
				fmt.Fprintln(os.Stderr, "DNS mode must be udp or tcp")
				return 2
			}
			dnsMode = args[4]
		}
		selected, err := revive.SelectProfileWithDNS(input, args[3], dnsMode)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		_, _ = os.Stdout.Write(selected)
		return 0
	}
	// Internal dry-run export used by CI; never changes Windows routes.
	if len(args) == 1 && args[0] == "tun-preview" {
		cfg, err := systemtun.BuildConfig(10808, "Ethernet")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		fmt.Println(string(cfg))
		return 0
	}
	cdnranges.Load(warpDir())
	if len(args) == 0 {
		return interactiveMenu()
	}
	switch args[0] {
	case "ranges":
		return runRanges(args[1:])
	case "menu":
		return interactiveMenu()
	case "connect", "smart":
		return runConnect(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "windscribe-test":
		return runWindscribeTest(args[1:])
	case "aether-test":
		return runAetherTest(args[1:])
	case "ca":
		return runCA(args[1:])
	case "warp":
		return runWarp(args[1:])
	case "strategies":
		return runStrategies(args[1:])
	case "scan":
		return runQuickScan(args[1:])
	case "path":
		return runPath(args[1:])
	case "revive":
		return runRevive(args[1:])
	case "access":
		return runAccess(args[1:])
	case "edges":
		return runEdges(args[1:])
	case "echo":
		return runEcho(args[1:])
	case "probe", "compare":
	case "help", "-h", "-help", "--help":
		fmt.Print(usageText)
		return 0
	default:
		fmt.Fprint(os.Stderr, usageText)
		return 2
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	var cfg probe.Config
	var attempts int
	var authorized bool
	flags.StringVar(&cfg.URL, "url", "", "destination URL (required)")
	flags.StringVar(&cfg.ServerName, "sni", "", "optional TLS SNI and certificate verification name")
	flags.StringVar(&cfg.Host, "host", "", "optional HTTP Host override")
	flags.StringVar(&cfg.ConnectAddr, "connect", "", "optional host:port for TCP dial")
	flags.StringVar(&cfg.Network, "network", "tcp", "tcp, tcp4 or tcp6")
	flags.DurationVar(&cfg.Timeout, "timeout", 8*time.Second, "per-trial timeout")
	flags.BoolVar(&cfg.Proof, "proof", false, "require a fresh challenge echoed by an HTTPS origin you control")
	if command == "probe" {
		flags.IntVar(&attempts, "repeat", 1, "bounded repetitions, 1..10")
	} else {
		flags.IntVar(&attempts, "rounds", 3, "paired rounds, 1..10")
		flags.BoolVar(&authorized, "authorized", false, "confirm tests target infrastructure you own or are permitted to test")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if cfg.URL == "" || attempts < 1 || attempts > 10 || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "url is required; repetitions/rounds must be 1..10; no extra arguments")
		return 2
	}
	enc := json.NewEncoder(os.Stdout)
	if command == "compare" {
		if !authorized {
			fmt.Fprintln(os.Stderr, "compare requires -authorized for controlled or permitted destinations")
			return 2
		}
		report, err := experiment.Run(context.Background(), experiment.Plan{Base: cfg, Rounds: attempts}, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if err := enc.Encode(report); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		// Comparison is informative, not a guarantee of success. Always zero if the
		// suite executed; outcomes are described in the JSON report.
		return 0
	}
	failed := false
	for i := 0; i < attempts; i++ {
		result, err := probe.Run(context.Background(), cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if err := enc.Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if !result.Success {
			failed = true
		}
	}
	if failed {
		return 1
	}
	return 0
}

// runEcho runs only on loopback; use an HTTPS reverse proxy under your control
// for any remote experiment. Raw HTTP is never exposed automatically.
func runEcho(args []string) int {
	flags := flag.NewFlagSet("echo", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:18080", "loopback listener address")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return 2
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		fmt.Fprintln(os.Stderr, "proof endpoint must bind to loopback; place a controlled HTTPS reverse proxy in front")
		return 2
	}
	server := &http.Server{Addr: *listen, Handler: proofserver.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 6 * time.Second, WriteTimeout: 6 * time.Second}
	fmt.Fprintln(os.Stderr, "controlled proof endpoint on", *listen)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, strings.TrimSpace(err.Error()))
		return 1
	}
	return 0
}

// runPath diagnoses DNS, TCP and certificate-verified TLS without sending HTTP.
func runPath(args []string) int {
	flags := flag.NewFlagSet("path", flag.ContinueOnError)
	var cfg pathdiag.Config
	var repeat int
	flags.StringVar(&cfg.URL, "url", "", "http(s) URL to diagnose")
	flags.StringVar(&cfg.SNI, "sni", "", "optional TLS identity for controlled tests")
	flags.StringVar(&cfg.ConnectAddr, "connect", "", "optional address to dial instead of URL destination")
	flags.StringVar(&cfg.Network, "network", "tcp", "tcp, tcp4 or tcp6")
	flags.DurationVar(&cfg.Timeout, "timeout", 8*time.Second, "per-attempt total timeout, max 30s")
	flags.IntVar(&repeat, "repeat", 1, "number of sequential low-volume attempts, 1..5")
	if flags.Parse(args) != nil || cfg.URL == "" || repeat < 1 || repeat > 5 || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: ktest path -url https://example.org [-network tcp4|tcp6] [-connect ip:port] [-sni name] [-repeat 1..5]")
		return 2
	}
	failed := false
	enc := json.NewEncoder(os.Stdout)
	for i := 0; i < repeat; i++ {
		result, err := pathdiag.Run(context.Background(), cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if enc.Encode(result) != nil {
			return 1
		}
		if result.TCPStatus != "ok" || (result.TLSStatus != "verified" && result.TLSStatus != "not_applicable") {
			failed = true
		}
	}
	if failed {
		return 1
	}
	return 0
}

// runAccess exposes a domain-scoped CONNECT proxy backed by the genuine
// SNI-Spoofing-Go local engine. No TLS MITM, root CA installation, or system
// proxy modification occurs.
func runAccess(args []string) int {
	fs := flag.NewFlagSet("access", flag.ContinueOnError)
	domain := fs.String("domain", "", "comma-separated exact HTTPS domains allowed through bridge")
	listen := fs.String("listen", "127.0.0.1:1089", "loopback HTTP CONNECT proxy")
	bridge := fs.String("bridge", "127.0.0.1:40443", "loopback SNI engine listener")
	engine := fs.String("engine", "", "optional local path to official SNI-Spoofing-Go CLI")
	engineSHA := fs.String("engine-sha256", "", "explicit SHA-256 digest for a reviewed newer upstream CLI")
	target := fs.String("connect", "", "upstream host:443 handled by SNI engine")
	fakeSNI := fs.String("fake-sni", "", "decoy TLS hostname used by SNI engine")
	fp := fs.String("utls", "firefox", "upstream fake TLS fingerprint")
	injector := fs.String("injector", "", "active or passive; passive default on macOS")
	fragment := fs.Bool("enable-fragment", false, "opt-in real ClientHello fragmentation")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *domain == "" {
		fmt.Fprintln(os.Stderr, "usage: ktest access -domain your-domain.example [-engine ./sni-spoofing-...] [-connect ip:443 -fake-sni decoy.example] [-listen 127.0.0.1:1089]")
		return 2
	}
	proxy, err := access.NewProxy(strings.Split(*domain, ","), *bridge)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var engineFailure <-chan error
	if *engine != "" {
		if *target == "" || *fakeSNI == "" {
			fmt.Fprintln(os.Stderr, "-engine requires -connect and -fake-sni")
			return 2
		}
		mode := *injector
		if mode == "" {
			mode = "active"
			if runtime.GOOS == "darwin" {
				mode = "passive"
			}
		}
		cfg := access.EngineConfig{Binary: *engine, SHA256: *engineSHA, Bridge: *bridge, Target: *target, FakeSNI: *fakeSNI, Fingerprint: *fp, Injector: mode, Fragment: *fragment}
		child, err := access.StartEngine(ctx, cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "SNI engine:", err)
			return 2
		}
		failed := make(chan error, 1)
		engineFailure = failed
		go func() {
			if err := <-child; ctx.Err() == nil {
				if err == nil {
					err = errors.New("SNI engine exited unexpectedly")
				}
				fmt.Fprintln(os.Stderr, "SNI engine exited:", err)
				failed <- err
				cancel()
			}
		}()
	} else if *target != "" || *fakeSNI != "" || *engineSHA != "" {
		fmt.Fprintln(os.Stderr, "-connect / -fake-sni / -engine-sha256 require -engine")
		return 2
	}
	fmt.Fprintln(os.Stderr, "HTTPS-only local proxy: http://"+*listen, "domains:", *domain)
	fmt.Fprintln(os.Stderr, "No global proxy, DNS, or certificate settings were changed.")
	if err := access.Listen(ctx, *listen, proxy); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if engineFailure != nil {
		select {
		case <-engineFailure:
			return 1
		default:
		}
	}
	return 0
}

// runRevive launches the latest locally saved upstream serverless profile
// using a separately installed official Xray CLI. No global system changes.
func runRevive(args []string) int {
	fs := flag.NewFlagSet("revive", flag.ContinueOnError)
	xray := fs.String("xray", "xray", "installed Xray executable")
	profile := fs.String("profile", "Serverless-for-Iran.json", "offline subscription JSON file")
	variant := fs.String("variant", "B", "serverless profile A or B")
	assets := fs.String("assets", "", "optional Xray geosite/geoip asset directory")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: ktest revive [-xray ./xray] [-profile ./Serverless-for-Iran.json] [-variant B] [-assets ./assets]")
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	err := revive.Run(ctx, revive.Config{XrayBinary: *xray, Profile: *profile, Variant: *variant, AssetDir: *assets, Output: os.Stderr})
	if err != nil {
		fmt.Fprintln(os.Stderr, "revive:", err)
		return 1
	}
	return 0
}

// runEdges chooses from a short explicit list; it never enumerates CDN CIDRs.
func runEdges(args []string) int {
	fs := flag.NewFlagSet("edges", flag.ContinueOnError)
	target := fs.String("url", "", "HTTPS URL for an authorized endpoint")
	ipList := fs.String("ips", "", "comma-separated explicit IPv4 or IPv6 addresses (max 12)")
	sni := fs.String("sni", "", "TLS SNI / certificate reference identity")
	host := fs.String("host", "", "HTTP Host / :authority")
	proof := fs.Bool("proof", false, "require fresh proof echoed by an origin under your control")
	authorized := fs.Bool("authorized", false, "confirm permission to probe these endpoints")
	rounds := fs.Int("rounds", 2, "1..3 requests per IP")
	timeout := fs.Duration("timeout", 6*time.Second, "per-request timeout, max 15s")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *target == "" || *ipList == "" || !*authorized {
		fmt.Fprintln(os.Stderr, "usage: ktest edges -authorized -url https://example.org -ips 192.0.2.10,2001:db8::10 [-sni name] [-host name] [-proof] [-rounds 2]")
		return 2
	}
	report, err := edges.Run(context.Background(), edges.Plan{
		URL: *target, IPs: strings.Split(*ipList, ","), SNI: *sni, Host: *host,
		Proof: *proof, Rounds: *rounds, Timeout: *timeout,
	}, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "edges:", err)
		return 2
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// interactiveMenu presents a managed, non-blocking CLI with auto-verification.
func interactiveMenu() int {
	return runInteractive(os.Stdin, os.Stdout, defaultBase())
}

// runQuickScan verifies selected CDN candidates through a real TLS connection.
// A reachable IP is not a verified working fronting route.
func runQuickScan(args []string) int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return runQuickScanContext(ctx, args)
}

func runQuickScanContext(parent context.Context, args []string) int {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	provider := flags.String("provider", "cloudflare", "cloudflare, akamai, google, fastly, meta, cloudfront or gcore")
	limit := flags.Int("limit", 300, "maximum unique CDN IPs, 1..300; whole scan bounded to 90s")
	cdnHost := flags.String("windscribe-cdn", "", "your proxied Cloudflare hostname whose origin is a Windscribe WStunnel server")
	cdnSNI := flags.String("sni", "", "TLS SNI for your CDN route (default: its hostname; certificate verified)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	*provider = strings.ToLower(strings.TrimSpace(*provider))
	if !cdnranges.Known(*provider) {
		fmt.Fprintln(os.Stderr, "provider must be one of: "+strings.Join(cdnranges.Providers, ", "))
		return 2
	}
	if flags.NArg() != 0 || *limit < 1 || *limit > 300 {
		fmt.Fprintln(os.Stderr, "usage: ktest scan [-provider cloudflare|akamai|google|fastly|meta|cloudfront|gcore] [-limit 1..300] [-windscribe-cdn your.hostname]")
		return 2
	}
	opts := wsOptions{cdnHost: *cdnHost, cdnSNI: *cdnSNI}
	if err := opts.validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if *cdnHost != "" && *provider != "cloudflare" {
		fmt.Fprintln(os.Stderr, "-windscribe-cdn requires -provider cloudflare")
		return 2
	}
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	fmt.Println("Network: current system route; an active VPN can affect these results.")
	dns := dnscheck.CheckGoogleDNS(ctx)
	fmt.Println("DNS preflight:", dns.Format())
	fmt.Println("An open DNS route does not prove a CDN or filtered website is reachable.")
	preset, err := edges.ScanCandidates(ctx, *provider, *limit)
	if err != nil {
		fmt.Fprintln(os.Stderr, "candidate source:", err)
		return 1
	}
	ips, target, source := preset.IPs, preset.URL, preset.Source
	fmt.Printf("CDN %s | %d source-backed candidate IPs | source: %s\n", *provider, len(ips), source)
	if *cdnHost != "" {
		u := newTerm(os.Stdout)
		u.Note("Own CDN route: TLS certificate + WebSocket 101 for %s; no OpenVPN credentials/authentication test", *cdnHost)
		b := newWSBridge(opts, nil, nil, u.Note)
		b.scanCDNEdges(ctx, ips)
		b.mu.Lock()
		found := append([]string(nil), b.edges...)
		b.mu.Unlock()
		if ctx.Err() != nil {
			u.Note("CDN route scan cancelled/timed out; results incomplete")
			return 1
		}
		if len(found) == 0 {
			return 1
		}
		if len(found) > 3 {
			found = found[:3]
		}
		u.Note("Candidate edges for -windscribe-cdn-edge: %s", strings.Join(found, ","))
		u.Note("WebSocket routing only. OpenVPN reply/auth/data are untested; use the Windscribe bridge and -verify-vpn.")
		return 0
	}
	fmt.Println("Target: 10 certificate-verified HTTPS responses. This does NOT prove arbitrary domain fronting.")
	scan, err := edges.ScanCDN(ctx, ips, target, 10, nil, func(ip string, r probe.Result, tried, passed int) {
		switch {
		case r.Success && r.TLSVersion != "" && r.Status >= 200 && r.Status < 300 && r.Error == "":
			fmt.Printf("[%d/%d] VERIFIED HTTPS %-18s (%d/%d)\n", tried, len(ips), ip, passed, 10)
		case tried%10 == 0:
			fmt.Printf("[%d/%d] scanned; %d/10 verified; latest %s: %s\n", tried, len(ips), passed, ip, r.Phase)
		}
	})
	if err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "CDN scan:", err)
		return 1
	}
	if ctx.Err() != nil {
		fmt.Printf("Scan cancelled after %d candidates. No fronting claim made.\n", scan.Attempted)
		return 0
	}
	fmt.Printf("Finished: attempted=%d verified HTTPS=%d/10 duration=%s\n", scan.Attempted, len(scan.VerifiedHTTP), scan.Duration.Round(time.Second))
	for _, ip := range scan.VerifiedHTTP {
		fmt.Println("Verified provider HTTPS:", ip)
	}
	if !scan.ReachedGoal {
		fmt.Println("No 10 verified candidates were found within the bounded scan. Do not label failed IPs as working.")
	}
	fmt.Println("Provider HTTPS success cannot be reused as a Windscribe route without testing your own origin.")
	fmt.Println("For your configured Windscribe CDN hostname use: ktest scan -windscribe-cdn your.hostname")
	return 0
}
