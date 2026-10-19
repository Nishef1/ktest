package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Nishef1/ktest/internal/cdnranges"
)

// rangesClient fetches provider lists directly, or through a local SOCKS
// listener (ktest's own Connect proxy) when the direct route is filtered.
func rangesClient(socks string) *http.Client {
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 15 * time.Second}
	if socks != "" {
		proxy, _ := url.Parse("socks5h://" + socks)
		transport.Proxy = http.ProxyURL(proxy)
	}
	return &http.Client{Transport: transport, Timeout: 60 * time.Second}
}

// runRanges shows or refreshes the complete CDN address inventory used by
// scans and fronting.
func runRanges(args []string) int {
	fs := flag.NewFlagSet("ranges", flag.ContinueOnError)
	update := fs.Bool("update", false, "refresh every provider from its official list (or RIPEstat ASN data)")
	via := fs.String("socks", "", "fetch through this local SOCKS5 proxy, e.g. a running ktest connect on 127.0.0.1:10800")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: ktest ranges [-update] [-socks 127.0.0.1:10800]")
		return 2
	}
	dir := warpDir()
	set := cdnranges.Load(dir)
	if *update {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		reports, err := cdnranges.Refresh(ctx, rangesClient(*via), dir)
		if err != nil && *via == "" && portFree(connectPort) != nil {
			fmt.Println("Direct refresh failed; retrying through the running ktest proxy")
			reports, err = cdnranges.Refresh(ctx, rangesClient(fmt.Sprintf("127.0.0.1:%d", connectPort)), dir)
		}
		for _, r := range reports {
			fmt.Println("  " + r.String())
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		set = cdnranges.Current()
	}
	for _, p := range cdnranges.Providers {
		r := set.Providers[p]
		if r == nil {
			fmt.Printf("  %-11s none\n", p)
			continue
		}
		fmt.Printf("  %-11s %6d prefixes  %10d addresses  updated %s  %s\n", p, len(r.V4)+len(r.V6), set.Size(p), r.Updated.Format("2006-01-02"), r.Source)
	}
	if set.Stale() {
		fmt.Println("  Inventory is due for refresh: ktest ranges -update (Connect also refreshes it in the background).")
	}
	return 0
}

// refreshRangesInBackground keeps the inventory current once a session is up,
// fetching through the session's own SOCKS listener so filtered provider
// pages still arrive.
func refreshRangesInBackground(ctx context.Context, socks string, logf func(string, ...any)) {
	dir := warpDir()
	if dir == "" || !cdnranges.Load(dir).Stale() {
		return
	}
	go func() {
		rctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		reports, err := cdnranges.Refresh(rctx, rangesClient(""), dir)
		if err != nil && rctx.Err() == nil {
			reports, err = cdnranges.Refresh(rctx, rangesClient(socks), dir)
		}
		if err == nil && logf != nil {
			for _, r := range reports {
				if r.Err == nil {
					logf("CDN ranges %s", r)
				}
			}
		}
	}()
}
