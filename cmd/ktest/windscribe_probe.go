package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nishef1/ktest/internal/wstunnel"
)

const defaultProbeSNIs = "python.org,pypi.org,www.speedtest.net,www.aparat.com,www.digikala.com,none"

type wsProbeCase struct{ entry, sni, transport string }
type wsProbeResult struct {
	wsProbeCase
	tcp, tls, websocket bool
	took                time.Duration
	stage, failure      string
}

// Probe only the outer carrier. It sends no OpenVPN authentication material.
func probeWSCarrier(ctx context.Context, transport string, cfg wstunnel.Config) wsProbeResult {
	r := wsProbeResult{wsProbeCase: wsProbeCase{cfg.Addr, cfg.SNI, transport}}
	began := time.Now()
	var c net.Conn
	var err error
	if transport == "stealth" {
		c, err = wstunnel.DialStealth(ctx, cfg)
	} else {
		c, err = wstunnel.Dial(ctx, cfg)
	}
	r.took = time.Since(began)
	if err == nil {
		r.tcp, r.tls, r.websocket = true, true, transport == "wstunnel"
		_ = c.Close()
		return r
	}
	r.stage = "tcp"
	var staged *wstunnel.StageError
	if errors.As(err, &staged) {
		r.stage = staged.Stage
		r.failure = trimDetail(staged.Err.Error())
	} else {
		r.failure = trimDetail(err.Error())
	}
	r.tcp = r.stage == "tls" || r.stage == "websocket"
	r.tls = r.stage == "websocket"
	return r
}

func parseProbeSNIs(raw string) ([]string, error) {
	var names []string
	seen := map[string]bool{}
	for _, name := range strings.Split(raw, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "none" {
			name = ""
		} else if !validHostname(name) {
			return nil, fmt.Errorf("invalid SNI %q; use a hostname or none", name)
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if len(names) == 0 || len(names) > 12 {
		return nil, errors.New("use 1..12 distinct SNIs")
	}
	return names, nil
}

// Resolve a location to one reproducible node. Its advertised entries stay
// fixed across every SNI and round; a different city is never substituted.
func selectWSProbeNode(c *wsNodeCatalog, target string) (wsNode, []wsEndpoint, error) {
	c.mu.RLock()
	nodes := map[string]wsNode{}
	for _, source := range wsCatalogURLs {
		list := c.lists[source.name]
		if time.Since(list.Fetched) > wsCatalogMaxAge || time.Until(list.Fetched) > 5*time.Minute {
			continue
		}
		for tcp, n := range list.nodes {
			if _, ok := nodes[tcp]; !ok {
				nodes[tcp] = n
			}
		}
	}
	c.mu.RUnlock()
	if net.ParseIP(target) != nil {
		n, ok := nodes[target]
		if !ok {
			return wsNode{}, nil, fmt.Errorf("no fresh provider mapping for TCP target %s", target)
		}
		endpoints := c.endpoints(target)
		if len(endpoints) == 0 {
			return wsNode{}, nil, errors.New("node snapshots conflict or have no alternate entries")
		}
		return n, endpoints, nil
	}
	groups := map[string]bool{}
	for _, n := range nodes {
		if strings.EqualFold(n.Group, target) {
			groups[n.Group] = true
		}
	}
	if len(groups) == 0 {
		for _, n := range nodes {
			if strings.Contains(strings.ToLower(n.Group), strings.ToLower(target)) {
				groups[n.Group] = true
			}
		}
	}
	if len(groups) != 1 {
		var matches []string
		for g := range groups {
			matches = append(matches, g)
		}
		sort.Strings(matches)
		if len(matches) > 8 {
			matches = matches[:8]
		}
		return wsNode{}, nil, fmt.Errorf("location must match one group; matches: %s; use the full location or requested TCP IP", strings.Join(matches, ", "))
	}
	var candidates []wsNode
	for _, n := range nodes {
		if groups[n.Group] {
			candidates = append(candidates, n)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].TCP < candidates[j].TCP })
	for _, n := range candidates {
		if endpoints := c.endpoints(n.TCP); len(endpoints) > 0 {
			return n, endpoints, nil
		}
	}
	return wsNode{}, nil, errors.New("no consistent fresh node entries for this location")
}

type wsProbeScore struct {
	wsProbeCase
	attempts, tcp, tls, websocket int
	elapsed                       time.Duration
	failure                       string
}

func runWSProbeCases(ctx context.Context, cases []wsProbeCase, rounds int, timeout time.Duration) []wsProbeScore {
	jobs := make(chan wsProbeCase)
	results := make(chan wsProbeResult)
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				if ctx.Err() != nil {
					return
				}
				cfg := wstunnel.Config{Addr: c.entry, Host: strings.Split(c.entry, ":")[0], SNI: c.sni, Dial: directDial, Timeout: timeout}
				if c.transport == "wstunnel" {
					cfg.VerifyPeer = windscribeServerCert
				}
				r := probeWSCarrier(ctx, c.transport, cfg)
				select {
				case results <- r:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for range rounds {
			for _, c := range cases {
				select {
				case jobs <- c:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	scores := map[wsProbeCase]*wsProbeScore{}
	for _, c := range cases {
		scores[c] = &wsProbeScore{wsProbeCase: c}
	}
	for r := range results {
		s := scores[r.wsProbeCase]
		s.attempts++
		if r.tcp {
			s.tcp++
		}
		if r.tls {
			s.tls++
		}
		if r.websocket {
			s.websocket++
		}
		if r.tls && (r.transport == "stealth" || r.websocket) {
			s.elapsed += r.took
		}
		if r.failure != "" {
			s.failure = r.stage + ": " + r.failure
		}
	}
	var ordered []wsProbeScore
	for _, s := range scores {
		ordered = append(ordered, *s)
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.transport != b.transport {
			return a.transport < b.transport
		}
		if a.websocket != b.websocket {
			return a.websocket > b.websocket
		}
		if a.tls != b.tls {
			return a.tls > b.tls
		}
		if a.elapsed != b.elapsed {
			return a.elapsed < b.elapsed
		}
		if a.entry != b.entry {
			return a.entry < b.entry
		}
		return a.sni < b.sni
	})
	return ordered
}

func runWindscribeTest(args []string) int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return runWindscribeTestContext(ctx, args, newTerm(os.Stdout))
}

func runWindscribeTestContext(parent context.Context, args []string, u *term, suggestions ...func(string)) int {
	fs := flag.NewFlagSet("windscribe-test", flag.ContinueOnError)
	base := fs.String("base", defaultBase(), "portable folder containing cache/windscribe-nodes.json")
	target := fs.String("target", "", "requested OpenVPN TCP IP or location name, e.g. Ashburn - Bles Park")
	entry := fs.String("entry", "", "explicit public Windscribe carrier IPv4 (optional, no guessed neighbours)")
	snis := fs.String("sni", defaultProbeSNIs, "1..12 comma-separated hostnames; none tests an empty SNI")
	transport := fs.String("transport", "wstunnel", "wstunnel, stealth, or both (Stealth proves TLS only)")
	rounds := fs.Int("rounds", 2, "repetitions per fixed entry and SNI, 1..3")
	timeout := fs.Duration("timeout", 4*time.Second, "per-attempt timeout, 1s..8s; whole comparison bounded to 60s")
	verify := fs.Bool("verify-vpn", false, "read-only CLI + system HTTPS exit-IP check; does not reconnect")
	cliOverride := fs.String("windscribe-cli", "", "absolute Windscribe CLI path")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	names, err := parseProbeSNIs(*snis)
	if err != nil || fs.NArg() != 0 || *rounds < 1 || *rounds > 3 || *timeout < time.Second || *timeout > 8*time.Second || (*transport != "wstunnel" && *transport != "stealth" && *transport != "both") {
		u.Line(toneFail, "Invalid probe options: SNIs 1..12, rounds 1..3, timeout 1s..8s, transport wstunnel/stealth/both")
		if err != nil {
			u.Note("%v", err)
		}
		return 2
	}
	if *entry != "" && !publicWSIP(*entry) {
		u.Line(toneFail, "-entry requires a public IPv4 address")
		return 2
	}
	if (*entry != "" && strings.TrimSpace(*target) != "") || (*verify && (*entry != "" || strings.TrimSpace(*target) != "")) {
		u.Line(toneFail, "Choose one: -target, -entry, or -verify-vpn")
		return 2
	}
	if !*verify && strings.TrimSpace(*target) == "" && *entry == "" {
		u.Line(toneFail, "Specify -target with a location/TCP IP, -entry with a carrier IP, or -verify-vpn")
		return 2
	}
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	cli, cliErr := windscribeCLIPath(*cliOverride)
	if *cliOverride != "" && cliErr != nil {
		u.Line(toneFail, "%v", cliErr)
		return 2
	}
	if *verify {
		return verifyWindscribeVPN(ctx, cli, u)
	}
	status := readWSStatus(ctx, cli)
	u.Heading("Windscribe SNI test", "Fixed entries; direct TCP; no credentials, reconnects, route or certificate changes.")
	if cliErr != nil || status.err != nil {
		u.Note("CLI unavailable: network/VPN state unknown; these results cannot establish the ISP's direct path")
	}
	if status.state == windscribeConnected || status.state == windscribeConnecting {
		u.Line(toneWarn, "Windscribe is %s; SNI comparison skipped to avoid testing through an active/changing VPN", status.state)
		u.Note("Use windscribe-test -verify-vpn to check a connected VPN without disconnecting")
		return 1
	}
	var changed atomic.Bool
	done := make(chan struct{})
	if status.state == windscribeDisconnected {
		go func() {
			defer close(done)
			tick := time.NewTicker(time.Second)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					if s := readWSStatus(ctx, cli); ctx.Err() == nil && s.state != windscribeDisconnected {
						changed.Store(true)
						cancel()
						return
					}
				}
			}
		}()
		defer func() { cancel(); <-done }()
	}
	var endpoints []wsEndpoint
	if *entry != "" {
		endpoints = []wsEndpoint{{*entry, "explicit override"}}
	} else {
		c := newWSNodeCatalog()
		cache := filepath.Join(*base, "cache", "windscribe-nodes.json")
		c.load(cache)
		n, eps, selectErr := selectWSProbeNode(c, strings.TrimSpace(*target))
		if selectErr != nil {
			_ = c.refresh(ctx, &http.Client{Timeout: 8 * time.Second}, cache, u.Note)
			n, eps, selectErr = selectWSProbeNode(c, strings.TrimSpace(*target))
		}
		if selectErr != nil {
			u.Line(toneFail, "%v", selectErr)
			return 1
		}
		endpoints = eps
		u.Note("Location %s; fixed requested=%s; entries are provider-advertised for this node", n.Group, n.TCP)
	}
	var cases []wsProbeCase
	for _, ep := range endpoints {
		for _, name := range names {
			for _, proto := range []string{"wstunnel", "stealth"} {
				if *transport == "both" || *transport == proto {
					cases = append(cases, wsProbeCase{net.JoinHostPort(ep.ip, "443"), name, proto})
				}
			}
		}
	}
	u.Note("%d comparisons, %d rounds, up to 6 concurrent attempts; OpenVPN/auth/data remain untested by this probe", len(cases), *rounds)
	scores := runWSProbeCases(ctx, cases, *rounds, *timeout)
	if status.state == windscribeDisconnected && ctx.Err() == nil && readWSStatus(ctx, cli).state != windscribeDisconnected {
		changed.Store(true)
	}
	working := 0
	for _, s := range scores {
		name := s.sni
		if name == "" {
			name = "(no SNI)"
		}
		successes := s.websocket
		ws := "n/a"
		if s.transport == "wstunnel" {
			ws = fmt.Sprintf("%d/%d", s.websocket, s.attempts)
		} else {
			successes = s.tls
		}
		avg := "--"
		if successes > 0 {
			avg = shortDur(s.elapsed / time.Duration(successes))
			working++
		}
		u.Printf("  %-8s entry=%-21s SNI=%-22s TCP=%d/%d TLS=%d/%d WS101=%-3s avg=%s\n", s.transport, s.entry, name, s.tcp, s.attempts, s.tls, s.attempts, ws, avg)
		if s.failure != "" {
			u.Note("%s", s.failure)
		}
	}
	if changed.Load() {
		u.Line(toneWarn, "VPN state changed during comparison; results are inconclusive")
		return 1
	}
	if ctx.Err() != nil {
		u.Line(toneWarn, "Comparison cancelled or timed out; zero-attempt rows are untested")
		return 1
	}
	u.Note("OpenVPN reply: not tested. Authentication: not tested. VPN data: not tested.")
	u.Note("WS101 ranks WebSocket reachability only; Stealth TLS alone does not prove an OpenVPN service.")
	for _, s := range scores {
		if s.transport == "wstunnel" && s.websocket == *rounds && s.attempts == *rounds && s.sni != "" {
			u.Note("Candidate SNI (outer transport only): %s. Try with connect -mode windscribe -windscribe-wstunnel-sni %s; authentication still belongs to Windscribe.", s.sni, s.sni)
			for _, suggest := range suggestions {
				suggest(s.sni)
			}
			break
		}
	}
	u.Note("For OpenVPN framing/auth stages, connect the Windscribe app through ktest's bridge; once connected run windscribe-test -verify-vpn.")
	if working == 0 {
		return 1
	}
	return 0
}
