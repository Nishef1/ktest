package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nishef1/ktest/internal/dnscheck"
	"github.com/Nishef1/ktest/internal/front"
	"github.com/Nishef1/ktest/internal/quickcheck"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

func newWarpManager(ctx context.Context, o connectOptions, proxy *smartproxy.Proxy, dns *dnscheck.Result, u *term, full bool) (*warpManager, error) {
	if o.mode == ModeWindscribe {
		return nil, errors.New("managed exits are prohibited in local-only Windscribe mode")
	}
	if !fileOK(aetherBinary(o.base)) {
		return nil, errors.New("Aether core missing; use Setup > Exit paths")
	}
	if warpDir() == "" {
		return nil, errors.New("per-user WARP configuration directory unavailable")
	}
	if err := os.MkdirAll(filepath.Clean(warpDir()), 0700); err != nil {
		return nil, err
	}
	key, core := networkSignature(ctx), coreFingerprint(o.base)
	history, err := cachedNetwork(key, core)
	if err != nil {
		u.Note("Saved network diagnosis not used: %v", err)
	}
	templates, err := loadAetherProfiles(o.base, "discovered", "discovered", o.mode)
	if err != nil {
		return nil, err
	}
	templates = filterAetherMethod(templates, o.aetherMethod)
	templates, err = supportedAetherProfiles(ctx, aetherBinary(o.base), templates)
	if err != nil {
		return nil, err
	}
	templates = measuredProfilesFirst(templates, history, o.mode)
	needECH := false
	for _, p := range templates {
		if p.has("--ech") {
			needECH = true
			break
		}
	}
	if !full && len(templates) > 0 && !templates[0].has("--ech") {
		if r, ok := history.Results[templates[0].id()]; ok && measurementScore(r, o.mode) < 1e12 && time.Since(r.Checked) < networkCacheTTL {
			needECH = false
		}
	}
	ech, ip := "", ""
	if needECH {
		fctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if cfg, addr, err := front.FetchCloudflareECH(fctx); err == nil {
			ech, ip = base64.StdEncoding.EncodeToString(cfg), addr
		}
		cancel()
	}
	profiles, err := loadAetherProfiles(o.base, ech, ip, o.mode)
	if err != nil {
		return nil, err
	}
	profiles = filterAetherMethod(profiles, o.aetherMethod)
	supported := map[string]bool{}
	for _, p := range templates {
		supported[p.id()] = true
	}
	var available []aetherProfile
	for _, p := range profiles {
		if supported[p.id()] && (!p.psiphon() || fileOK(psiphonCore(o.base))) {
			available = append(available, p)
		}
	}
	if len(available) == 0 {
		return nil, errors.New("no supported profile matches this mode/method; check cores and profiles/aether-profiles.txt")
	}
	available = recoveryProfilesFirst(available, history, o.mode)
	if len(history.Results) > 0 {
		u.Note("Reusing this network's measured profile order; checking live tunnels again")
	}
	return &warpManager{o: o, proxy: proxy, dns: dns, t: u, profs: available, ech: ech, echIP: ip, network: key, core: core}, nil
}

// All destinations are neutral/public. Never probe an AI service through an
// unverified exit, even when the user explicitly requests a full diagnosis.
func benchmarkAetherRoute(ctx context.Context, socks string, speed bool) aetherMeasurement {
	r := aetherMeasurement{Checked: time.Now(), State: "failed", Attempts: 1}
	began := time.Now()
	ip, country, err := probeExitLocation(ctx, socks)
	r.ExitIP, r.Country = ip, country
	if err != nil {
		r.State = "egress-rejected"
		r.Failure = err.Error()
		return r
	}
	r.Successes = 1
	latencies := []float64{float64(time.Since(began)) / float64(time.Millisecond)}
	tr := &http.Transport{MaxResponseHeaderBytes: 32 << 10, Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 4 * time.Second,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return smartproxy.DialVia(ctx, socks, host, port, 4*time.Second)
		}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	_, portText, _ := net.SplitHostPort(socks)
	port, portErr := strconv.Atoi(portText)
	if portErr != nil {
		r.Failure = "invalid local SOCKS address"
		return r
	}
	for _, sample := range quickcheck.Run(ctx, port, 8*time.Second) {
		if sample.Skipped {
			continue
		}
		r.Attempts++
		if sample.Success {
			r.Successes++
			latencies = append(latencies, float64(sample.Took)/float64(time.Millisecond))
		}
	}
	sort.Float64s(latencies)
	r.LatencyMS = latencies[len(latencies)/2]
	r.State = "verified"
	if _, _, err := parseForeignTrace("ip=" + ip + "\nloc=" + country); err != nil {
		r.State = "carrier"
		r.Failure = "carrier works; AI exit policy rejects this country"
	}
	if speed && ctx.Err() == nil {
		started := time.Now()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://speed.cloudflare.com/__down?bytes=131072", nil)
		if resp, err := client.Do(req); err == nil {
			n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 131073))
			resp.Body.Close()
			if err == nil && resp.StatusCode == 200 && n == 131072 {
				r.BytesPerSecond = float64(n) / time.Since(started).Seconds()
			}
		}
	}
	return r
}

type measuredAetherExit struct {
	*warpFound
	result aetherMeasurement
}

// Compare only before exposing the first exit to application traffic. Once
// selected, protected streams retain the existing session-pinning policy.
func (m *warpManager) compare(ctx context.Context, limit int, speed bool, indices []int) []measuredAetherExit {
	if indices == nil {
		for i := range m.profs {
			indices = append(indices, i)
		}
	}
	if m.attempted == nil {
		m.attempted = map[string]bool{}
	}
	var mu sync.Mutex
	next := 0
	var found []measuredAetherExit
	hasForeign := func() bool {
		for _, r := range found {
			if r.result.State == "verified" {
				return true
			}
		}
		return false
	}
	var workers sync.WaitGroup
	var speedSlots atomic.Int32
	speedSlots.Store(16) // at most 2 MiB of optional download payload per comparison
	count := 2
	if limit == 1 {
		count = 1
	}
	for range count {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for ctx.Err() == nil {
				if m.monitor != nil && m.monitor.Connected() {
					return
				}
				mu.Lock()
				if next >= len(indices) || (limit > 0 && len(found) >= limit && (hasForeign() || m.o.mode == ModeWindscribeAether)) {
					mu.Unlock()
					return
				}
				i := indices[next]
				next++
				p := m.profs[i]
				m.attempted[p.id()] = true
				mu.Unlock()
				// A slow/blocked family cannot consume the whole comparison.
				attempt, cancel := context.WithTimeout(ctx, profileAttemptBudget(p))
				up, rc, failure := m.try(attempt, i, p)
				// The core must outlive this probe deadline when selected. try
				// uses m's session context for the process, attempt for readiness.
				r := measurementFor(p)
				if up {
					r = benchmarkAetherRoute(attempt, fmt.Sprintf("127.0.0.1:%d", aetherPort(i)), speed && speedSlots.Add(-1) >= 0)
					r.ID, r.Label, r.Method = p.id(), p.Label, p.method()
				} else {
					r.Failure = failure
					if attempt.Err() == context.DeadlineExceeded && ctx.Err() == nil {
						r.State = "timeout"
						r.Failure = "attempt deadline exceeded: " + failure
					}
				}
				cancel()
				if ctx.Err() != nil {
					if !m.diagnosis && m.processCtx != nil && m.processCtx.Err() == nil {
						r.State = "timeout"
						r.Failure = "discovery budget expired; other candidates will be preferred on retry"
						_ = saveMeasurement(m.network, m.core, r)
					}
					if rc != nil {
						rc.stop()
					}
					return
				}
				if m.diagnosis {
					m.measureMu.Lock()
					m.measurements = append(m.measurements, r)
					m.measureMu.Unlock()
				} else {
					if err := saveMeasurement(m.network, m.core, r); err != nil {
						m.t.Note("Diagnosis not saved: %v", err)
					}
				}
				m.t.Line(toneInfo, "%s: %s", p.Label, r.detail())
				if !up || measurementScore(r, m.o.mode) >= 1e12 {
					if rc != nil {
						rc.stop()
					}
					continue
				}
				mu.Lock()
				if limit > 0 && len(found) >= limit {
					if !hasForeign() && r.State == "verified" {
						old := found[len(found)-1]
						found[len(found)-1] = measuredAetherExit{&warpFound{p: p, port: aetherPort(i), rc: rc}, r}
						mu.Unlock()
						old.rc.stop()
						continue
					}
					mu.Unlock()
					rc.stop()
					continue
				}
				found = append(found, measuredAetherExit{&warpFound{p: p, port: aetherPort(i), rc: rc}, r})
				mu.Unlock()
				if limit == 0 {
					rc.stop()
				} // diagnosis retains measurements, not every tunnel
			}
		}()
	}
	workers.Wait()
	sort.SliceStable(found, func(i, j int) bool {
		return measurementScore(found[i].result, m.o.mode) < measurementScore(found[j].result, m.o.mode)
	})
	return found
}

func runAetherDiagnosis(ctx context.Context, u *term, base string, speed bool, budget time.Duration) int {
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	u.Heading("Aether comparison", "Starts temporary local cores; neutral HTTPS samples only. No system TUN, account login, or route changes.")
	cli, _ := windscribeCLIPath("")
	status := readWSStatus(ctx, cli)
	if status.state == windscribeConnected || status.state == windscribeConnecting || len(activeKtestTUNs()) > 0 {
		u.Line(toneWarn, "An active/changing VPN or ktest TUN would contaminate ISP measurements. Comparison skipped; leave the current VPN untouched.")
		return 1
	}
	if status.err != nil {
		u.Note("Windscribe state unavailable; results describe the current system route and may include another VPN.")
	}
	o := defaultConnectOptions(base)
	o.mode, o.tun, o.aetherMethod = ModeAether, false, "auto"
	m, err := newWarpManager(ctx, o, nil, nil, u, true)
	if err != nil {
		u.Line(toneWarn, "%v", err)
		return 1
	}
	m.diagnosis = true
	u.Note("Budget %s · up to two profiles at once · up to 8 KiB website bodies per profile", budget)
	if speed {
		u.Note("Small-transfer sampling: at most 128 KiB per profile and 2 MiB total payload, excluding tunnel setup/protocol overhead.")
	}
	var changed atomic.Bool
	if status.state == windscribeDisconnected {
		go func() {
			tick := time.NewTicker(2 * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					if next := readWSStatus(ctx, cli); ctx.Err() == nil && next.state != windscribeDisconnected {
						changed.Store(true)
						cancel()
						return
					}
				}
			}
		}()
	}
	mctx, stop := context.WithCancel(ctx)
	defer stop()
	m.processCtx = mctx
	results := m.compare(ctx, 0, speed, nil)
	for _, r := range results {
		r.rc.stop()
	}
	if parent.Err() != nil {
		u.Note("Comparison cancelled; incomplete diagnosis was not saved.")
		return 1
	}
	check, stopCheck := context.WithTimeout(context.Background(), 4*time.Second)
	key := networkSignature(check)
	if status.state == windscribeDisconnected && readWSStatus(check, cli).state != windscribeDisconnected {
		changed.Store(true)
	}
	stopCheck()
	if changed.Load() || key == "" || key != m.network {
		u.Line(toneWarn, "Network/VPN state changed or could not be confirmed. Comparison is inconclusive; saved results were kept.")
		return 1
	}
	for _, r := range m.measurements {
		if err := saveMeasurement(m.network, m.core, r); err != nil {
			u.Line(toneWarn, "Diagnosis not saved: %v", err)
			break
		}
	}
	printNetworkRecommendations(u, m.network, m.core, m.profs)
	if ctx.Err() != nil {
		u.Line(toneWarn, "Comparison stopped at its budget/cancellation; unfinished profiles are untested, not blocked.")
	}
	if len(results) == 0 {
		return 1
	}
	return 0
}

func runAetherTest(args []string) int {
	fs := flag.NewFlagSet("aether-test", flag.ContinueOnError)
	base := fs.String("base", defaultBase(), "portable folder")
	speed := fs.Bool("speed", false, "add a bounded 128 KiB sample per working route")
	budget := fs.Duration("budget", 3*time.Minute, "overall comparison budget, 15s..10m")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *budget < 15*time.Second || *budget > 10*time.Minute {
		fmt.Fprintln(os.Stderr, "budget must be 15s..10m")
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return runAetherDiagnosis(ctx, newTerm(os.Stdout), *base, *speed, *budget)
}
