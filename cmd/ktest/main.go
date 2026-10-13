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
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/experiment"
	"github.com/Nishef1/ktest/internal/pathdiag"
	"github.com/Nishef1/ktest/internal/probe"
	"github.com/Nishef1/ktest/internal/proofserver"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
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
