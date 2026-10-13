package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Nishef1/ktest/internal/experiment"
	"github.com/Nishef1/ktest/internal/probe"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
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
