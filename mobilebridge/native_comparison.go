package mobilebridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
	"github.com/Nishef1/ktest/internal/quickcheck"
	"github.com/Nishef1/ktest/internal/smartproxy"
	"github.com/Nishef1/ktest/internal/tlsshape"
)

var nativeComparisonActive atomic.Bool
var nativeCompareMu sync.Mutex
var nativeCompareCancel context.CancelFunc

func CancelAetherNativeComparison() {
	nativeCompareMu.Lock()
	defer nativeCompareMu.Unlock()
	if nativeCompareCancel != nil {
		nativeCompareCancel()
	}
}

// Select a bounded, diverse set of real H2 profiles. No ECH or other carrier
// obscures the comparison of the directly measured TLS combinations.
func nativeComparisonCandidates(profiles []aether.Profile) []aether.Profile {
	var out, alternatives []aether.Profile
	seen := map[string]bool{}
	families := map[bool]bool{}
	for _, p := range profiles {
		if p.Method() != "masque-h2" || p.Has("--ech") || p.LocalCarrier() || (p.Has("--upstream") && p.ExitNode() == "") {
			continue
		}
		key := tlsshape.ActiveSummary(p) + strconv.FormatBool(p.Has("-6"))
		if seen[key] {
			continue
		}
		seen[key] = true
		if !families[p.Has("-6")] {
			out = append(out, p)
			families[p.Has("-6")] = true
		} else {
			alternatives = append(alternatives, p)
		}
	}
	out = append(out, alternatives...)
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

type nativeComparisonSample struct {
	profile            aether.Profile
	successes, attempts int
	latency            time.Duration
	bytesPerSecond     float64
}

// Only a validated HTTPS exit plus successful application requests qualifies.
// Speed is optional evidence; one blocked speed endpoint cannot veto a tunnel.
func betterNativeSample(a, b nativeComparisonSample) bool {
	if a.successes != b.successes {
		return a.successes > b.successes
	}
	if a.attempts != b.attempts {
		return a.attempts < b.attempts
	}
	if a.bytesPerSecond > 0 && b.bytesPerSecond > 0 && a.bytesPerSecond != b.bytesPerSecond {
		return a.bytesPerSecond > b.bytesPerSecond
	}
	return a.latency < b.latency
}

func nativeTransfer(ctx context.Context, socks string) float64 {
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return smartproxy.DialVia(ctx, socks, host, port, 4*time.Second)
		}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 6 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://speed.cloudflare.com/__down?bytes=131072", nil)
	if err != nil {
		return 0
	}
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 131073))
	if err != nil || resp.StatusCode != 200 || n != 131072 {
		return 0
	}
	return float64(n) / time.Since(started).Seconds()
}

// CompareAetherNative is an explicit offline diagnostic. It starts at most
// three temporary checksum-verified Aether processes, sequentially, and
// never installs a TUN or creates identities just for the benchmark.
func CompareAetherNative(nativeDir, privateDir string) (string, error) {
	if !calibrateMu.TryLock() {
		return "", errors.New("another Aether measurement is running")
	}
	defer calibrateMu.Unlock()
	if !proxyStartMu.TryLock() {
		return "", errors.New("finish the current startup before comparing")
	}
	if routeWorkActive() {
		proxyStartMu.Unlock()
		return "", errors.New("disconnect before comparing Aether")
	}
	scanMu.Lock()
	scanning := scanState.Running
	scanMu.Unlock()
	if scanning {
		proxyStartMu.Unlock()
		return "", errors.New("stop the CDN scan before comparing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	nativeCompareMu.Lock()
	nativeCompareCancel = cancel
	nativeComparisonActive.Store(true)
	nativeCompareMu.Unlock()
	proxyStartMu.Unlock()
	defer func() {
		cancel()
		nativeCompareMu.Lock()
		nativeCompareCancel = nil
		nativeComparisonActive.Store(false)
		nativeCompareMu.Unlock()
	}()
	o := nativeOptions{method: "masque-h2", libraryDir: nativeDir, privateDir: privateDir, stateDir: filepath.Join(privateDir, "aether")}
	key := nativeTLSHistoryKey(o)
	if key == "" {
		return "", errors.New("network identity is unavailable")
	}
	profiles, err := nativeAutoCandidatesWithECHAndPrivateDir(false, "", "", privateDir)
	if err != nil {
		return "", err
	}
	profiles = nativeComparisonCandidates(profiles)
	if len(profiles) == 0 || !aether.ReadyIdentity(profiles[0], o.stateDir) {
		return "", errors.New("a valid existing MASQUE identity is required; connect Aether once first")
	}
	var lines []string
	var best nativeComparisonSample
	for _, p := range profiles {
		if ctx.Err() != nil {
			break
		}
		if nativeTLSHistoryKey(o) != key {
			return "", errors.New("network or settings changed; comparison discarded")
		}
		attempt, stop := context.WithTimeout(ctx, 35*time.Second)
		candidate := o
		quick := aether.QuickScanProfile(p)
		candidate.profile = &quick
		core, err := launchNative(attempt, "aether", candidate)
		if err != nil {
			stop()
			lines = append(lines, p.Label+": startup failed")
			continue
		}
		_, err = waitNative(attempt, "aether", core)
		stop()
		if err != nil {
			core.stop()
			lines = append(lines, p.Label+": HTTPS exit not verified")
			continue
		}
		sample := nativeComparisonSample{profile: p}
		_, portText, _ := net.SplitHostPort(core.address)
		port, _ := strconv.Atoi(portText)
		var timings []time.Duration
		for _, result := range quickcheck.Run(ctx, port, 5*time.Second) {
			if !result.Skipped {
				sample.attempts++
			}
			if result.Success {
				sample.successes++
				timings = append(timings, result.Took)
			}
		}
		if len(timings) > 0 {
			sort.Slice(timings, func(i, j int) bool { return timings[i] < timings[j] })
			sample.latency = timings[len(timings)/2]
			sample.bytesPerSecond = nativeTransfer(ctx, core.address)
		}
		core.stop()
		lines = append(lines, fmt.Sprintf("%s: %d/%d requests · %d ms · %.0f KiB/s (0 = not measured)", p.Label, sample.successes, sample.attempts, sample.latency.Milliseconds(), sample.bytesPerSecond/1024))
		if sample.successes > 0 && (best.successes == 0 || betterNativeSample(sample, best)) {
			best = sample
		}
	}
	if ctx.Err() != nil || nativeTLSHistoryKey(o) != key {
		return strings.Join(lines, "\n") + "\nComparison incomplete; no winner saved.", nil
	}
	if best.successes == 0 {
		return strings.Join(lines, "\n") + "\nNo usable native sample; no winner saved.", nil
	}
	if err := saveNativeTLSHistory(privateDir, key, best.profile); err != nil {
		return "", fmt.Errorf("native comparison winner could not be saved: %w", err)
	}
	return strings.Join(lines, "\n") + "\nSaved winner for MASQUE H2: " + best.profile.Label + " · " + tlsshape.ActiveSummary(best.profile), nil
}

// AetherTLSCapabilities reports the exact APK binary's advertised options.
// It does not enable new options or claim their values work on this network.
func AetherTLSCapabilities(nativeDir string) (string, error) {
	paths, err := aether.AndroidBundlePaths(nativeDir, runtime.GOARCH)
	if err != nil {
		return "", err
	}
	known, err := aether.InspectOptions(context.Background(), paths.Aether)
	if err != nil {
		return "", err
	}
	lines := []string{"PattNG Aether " + paths.Version}
	for _, flag := range []string{"--tls-ciphers", "--tls13-ciphers", "--tls-groups", "--tls-key-shares", "--tls-sigalgs", "--tls-cert-compression", "--tls-alps", "--enable-ech-grease", "--disable-extension-permutation", "--tls-verify"} {
		state := "not advertised"
		if known[flag] {
			state = "available"
		}
		lines = append(lines, flag+": "+state)
	}
	return strings.Join(lines, "\n"), nil
}
