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
	"github.com/Nishef1/ktest/internal/experiment"
	"github.com/Nishef1/ktest/internal/pathdiag"
	"github.com/Nishef1/ktest/internal/probe"
	"github.com/Nishef1/ktest/internal/proofserver"
	"github.com/Nishef1/ktest/internal/revive"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) > 0 && args[0] == "revive" {
		return runRevive(args[1:])
	}
	if len(args) > 0 && args[0] == "access" {
		return runAccess(args[1:])
	}
	if len(args) > 0 && args[0] == "path" {
		return runPath(args[1:])
	}
	if len(args) > 0 && args[0] == "echo" {
		return runEcho(args[1:])
	}
	if len(args) == 0 || (args[0] != "probe" && args[0] != "compare") {
		fmt.Fprintln(os.Stderr, "usage: ktest probe|compare -url https://example.org [options]")
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
