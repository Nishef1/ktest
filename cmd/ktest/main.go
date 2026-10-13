package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Nishef1/ktest/internal/probe"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "probe" {
		fmt.Fprintln(os.Stderr, "usage: ktest probe -url https://example.org [-sni name] [-host name] [-connect ip:port] [-network tcp|tcp4|tcp6] [-repeat 1..10] [-timeout 8s]")
		os.Exit(2)
	}
	flags := flag.NewFlagSet("probe", flag.ContinueOnError)
	var cfg probe.Config
	var repeat int
	flags.StringVar(&cfg.URL, "url", "", "destination URL (required)")
	flags.StringVar(&cfg.ServerName, "sni", "", "TLS SNI and certificate name; verified, never skipped")
	flags.StringVar(&cfg.Host, "host", "", "override HTTP Host to test service routing")
	flags.StringVar(&cfg.ConnectAddr, "connect", "", "optional TCP dial host:port override")
	flags.StringVar(&cfg.Network, "network", "tcp", "tcp, tcp4, or tcp6")
	flags.DurationVar(&cfg.Timeout, "timeout", 8*time.Second, "per-probe timeout")
	flags.IntVar(&repeat, "repeat", 1, "number of bounded sequential probes, 1..10")
	if err := flags.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	if cfg.URL == "" || repeat < 1 || repeat > 10 {
		fmt.Fprintln(os.Stderr, "url is required; repeat must be between 1 and 10")
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	failed := false
	for i := 0; i < repeat; i++ {
		result, err := probe.Run(context.Background(), cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := enc.Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if !result.Success {
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}
