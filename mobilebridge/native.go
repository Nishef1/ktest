package mobilebridge

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
	"github.com/Nishef1/ktest/internal/egresscheck"
	"github.com/Nishef1/ktest/internal/front"
)

type nativeOptions struct {
	method, libraryDir, stateDir string
	// viaFast carries Aether through a private Fast proxy (carrier address).
	viaFast    bool
	privateDir string
	carrier    string
	profile    *aether.Profile // automatic discovery preserves exact variants
}

type nativeCore struct {
	address string
	method  string
	cancel  context.CancelFunc
	done    chan struct{}
	err     error // read only after done closes
	log     *stageLog
}

// StartNativeProxy runs the packaged Aether core, including its existing Tor
// and Psiphon backends. The core owns enrollment, gateway scans and reconnect;
// KTest owns process lifetime and the existing fail-closed route policy.
// Both paths come from Android ApplicationInfo/filesDir, never a download.
func StartNativeProxy(mode, method, libraryDir, stateDir string) (string, error) {
	if mode != "aether" && mode != "tor" && mode != "psiphon" {
		return "", errors.New("managed native startup requires Aether, Tor or Psiphon mode")
	}
	return startProxy(mode, "", &nativeOptions{method: method, libraryDir: libraryDir, stateDir: stateDir}, "")
}

func nativeProfile(mode, method string, viaFast bool) (aether.Profile, error) {
	if !aether.ValidMethod(method) {
		return aether.Profile{}, errors.New("unknown Aether method")
	}
	if mode == "tor" {
		if method != "" && method != "auto" {
			return aether.Profile{}, errors.New("Tor uses its dedicated Aether backend")
		}
		return aether.Profile{Label: "Tor-only", Args: []string{"--tor-only"}}, nil
	}
	profiles, err := aether.ParseProfiles(aether.DefaultProfiles, "", "")
	if err != nil {
		return aether.Profile{}, err
	}
	profiles = aether.FilterMethod(aether.ProfilesForMode(profiles, mode), method)
	if viaFast && mode == "aether" {
		profiles = tcpCarriedProfiles(profiles)
		if len(profiles) == 0 {
			return aether.Profile{}, errors.New("through Fast only TCP methods work (MASQUE, Gool or MASQUE-in-MASQUE over HTTP/2); choose one of those")
		}
	}
	if len(profiles) == 0 {
		return aether.Profile{}, errors.New("selected method is incompatible with this mode")
	}
	// Default means the first shipped compatible profile, not an invented
	// cross-protocol scanner. Users can select another existing native method.
	return profiles[0], nil
}

// nativeAutoCandidates are distinct WARP transports, not Psiphon/Tor
// substitutes. Android Auto must try another protocol after a failed native
// exit rather than calling the first profile "automatic".
func nativeAutoCandidates(viaCarrier bool) ([]aether.Profile, error) {
	return nativeAutoCandidatesWithECH(viaCarrier, "", "")
}

func nativeAutoCandidatesWithECH(viaCarrier bool, ech, ip string) ([]aether.Profile, error) {
	profiles, err := aether.ParseProfiles(aether.DefaultProfiles, ech, ip)
	if err != nil {
		return nil, err
	}
	profiles = aether.ProfilesForMode(profiles, "aether")
	if viaCarrier {
		profiles = tcpCarriedProfiles(profiles)
	}
	var candidates []aether.Profile
	for _, p := range profiles {
		if p.Psiphon() || p.Has("--tor-only") {
			continue
		}
		candidates = append(candidates, p)
	}
	if len(candidates) == 0 {
		return nil, errors.New("no compatible WARP transport for this carrier")
	}
	// The native startup budget is shared across candidates. Probe the
	// simplest, no-ECH profile of each independent transport first; without
	// this a set of H2/ECH variants can exhaust the startup budget before H3
	// or WireGuard is even attempted. Preserve the remaining candidates.
	methods := make(map[string]bool)
	ordered := make([]aether.Profile, 0, len(candidates))
	taken := make([]bool, len(candidates))
	for i, p := range candidates {
		if p.Has("--ech") || methods[p.Method()] {
			continue
		}
		methods[p.Method()] = true
		taken[i] = true
		ordered = append(ordered, p)
	}
	for i, p := range candidates {
		if !taken[i] {
			ordered = append(ordered, p)
		}
	}
	return ordered, nil
}

// launchVerifiedNativeAuto reuses the upstream Aether's own gateway scan
// within each transport. Only independent protocol/profile attempts happen
// here. The first actual foreign HTTPS exit wins; failed native processes
// are stopped before the next candidate starts.
func launchVerifiedNativeAuto(ctx context.Context, o nativeOptions) (*nativeCore, observedExit, error) {
	// Discover ECH only once per automatic startup. Blocked ECH lookup must
	// not suppress ordinary MASQUE H2/H3 or WireGuard profiles.
	ech, ip := "", ""
	discoveryCtx, stopDiscovery := context.WithTimeout(ctx, 3*time.Second)
	if cfg, address, discoveryErr := front.FetchCloudflareECH(discoveryCtx); discoveryErr == nil {
		ech, ip = base64.StdEncoding.EncodeToString(cfg), address
	}
	stopDiscovery()
	profiles, err := nativeAutoCandidatesWithECH(o.carrier != "", ech, ip)
	if err != nil {
		return nil, observedExit{}, err
	}
	var lastErr error
	for _, profile := range profiles {
		if err := ctx.Err(); err != nil {
			return nil, observedExit{}, err
		}
		candidate := o
		candidate.profile = &profile
		core, err := launchNative(ctx, "aether", candidate)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", profile.Label, err)
			continue
		}
		attempt, cancel := context.WithTimeout(ctx, aether.AttemptTimeout(profile)+15*time.Second)
		checked, err := waitNative(attempt, "aether", core)
		cancel()
		if err == nil {
			return core, checked, nil
		}
		core.stop()
		lastErr = fmt.Errorf("%s: %w", profile.Label, err)
	}
	return nil, observedExit{}, fmt.Errorf("no Aether Auto transport passed foreign HTTPS verification: %w", lastErr)
}

func launchNative(ctx context.Context, mode string, o nativeOptions) (*nativeCore, error) {
	p, err := nativeProfile(mode, o.method, o.carrier != "")
	if o.profile != nil {
		p, err = *o.profile, nil
	}
	if err != nil {
		return nil, err
	}
	paths, err := aether.AndroidBundlePaths(o.libraryDir, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(o.stateDir) || filepath.Clean(o.stateDir) == filepath.Clean(o.libraryDir) {
		return nil, errors.New("native state requires a separate absolute private directory")
	}
	if err := os.MkdirAll(o.stateDir, 0700); err != nil {
		return nil, fmt.Errorf("native private state: %w", err)
	}
	if filepath.Base(o.stateDir) == "aether" {
		legacy := filepath.Join(filepath.Dir(o.stateDir), "automatic-exits")
		if _, err := aether.MigrateIdentityFiles(o.stateDir, legacy); err != nil {
			return nil, fmt.Errorf("migrate existing Android WARP identity: %w", err)
		}
	}
	supported, err := aether.InspectProfiles(ctx, paths.Aether, []aether.Profile{p})
	if err != nil {
		return nil, err
	}
	if len(supported) == 0 {
		return nil, errors.New("packaged Aether does not support this profile")
	}
	// InspectProfiles normalizes renamed Aether CLI flags for this exact
	// binary. Launch the accepted profile, not its pre-normalized template.
	p = supported[0]
	// Identity bootstrap precedes gateway probing, not the user's VPN
	// permission flow. It is a bounded, best-effort anti-DPI registration
	// attempt; no helper may silently become the user's final exit method.
	if err := bootstrapAndroidWARP(ctx, o, paths, p); err != nil {
		return nil, fmt.Errorf("WARP identity setup: %w", err)
	}
	if edges := psiphonEdges(p, o.privateDir); len(edges) > 0 {
		// Edges this network verified in CDN scans are tried first by
		// Psiphon's fronting; its own built-in lists still follow.
		withEdges := aether.Profile{Label: p.Label, Args: append(append([]string(nil), p.Args...), "--psiphon-cdn-ips", strings.Join(edges, ","))}
		if ok, inspectErr := aether.InspectProfiles(ctx, paths.Aether, []aether.Profile{withEdges}); inspectErr == nil && len(ok) > 0 {
			p = ok[0]
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	address := listener.Addr().String()
	_ = listener.Close() // Aether binds its own socket; no inherited-fd API.
	args := paths.ProfileArgs(p, port, o.stateDir)
	if p.LocalCarrier() {
		args, err = aether.BindLocalCarrier(args, o.carrier)
		if err != nil {
			return nil, err
		}
	} else if o.carrier != "" {
		args = append(args, "--upstream", "socks5://"+o.carrier)
	}
	runCtx, cancel := context.WithCancel(context.Background())
	cleanupDNS := func() {}
	if p.Psiphon() && !p.Has("--psiphon-config") {
		path, cleanup, err := preparePsiphonDNS(runCtx, o.stateDir, p.ID())
		if err != nil {
			cancel()
			return nil, fmt.Errorf("native Psiphon DNS bootstrap: %w", err)
		}
		cleanupDNS = cleanup
		args = append(args, "--psiphon-config", path)
	}
	n := &nativeCore{address: address, method: p.Method(), cancel: cancel, done: make(chan struct{}), log: newStageLog()}
	go func() {
		defer close(n.done)
		defer cleanupDNS()
		// Raw native output can contain identifiers or credentials. Only
		// redacted warnings reach the UI; nothing goes to logcat or storage.
		n.err = aether.Run(runCtx, paths.Aether, args, n.log)
	}()
	return n, nil
}

// psiphonEdges are recently verified CDN edges of providers Psiphon fronts
// through, best providers first, bounded so the command line stays short.
func psiphonEdges(p aether.Profile, privateDir string) []string {
	if !p.Psiphon() || p.Has("--psiphon-cdn-ips") || privateDir == "" {
		return nil
	}
	var out []string
	for _, provider := range []string{"akamai", "cloudflare", "fastly", "cloudfront"} {
		for _, ip := range loadVerifiedCDNEdges(privateDir, provider) {
			if len(out) == 40 {
				return out
			}
			out = append(out, ip)
		}
	}
	return out
}

func (n *nativeCore) stop() {
	n.cancel()
	<-n.done // shared runner bounds Wait and terminates owned descendants
}

func verifyModeUpstream(ctx context.Context, mode, address string) (observedExit, error) {
	checked, err := verifyLocalUpstream(ctx, address)
	if err == nil && mode == "tor" {
		err = egresscheck.ProbeTorExit(ctx, checked.Address)
	}
	return checked, err
}

func waitNative(ctx context.Context, mode string, n *nativeCore) (observedExit, error) {
	checked, err := waitNativeWithProbe(ctx, mode, n, verifyModeUpstream)
	if last := n.log.last(); err != nil && last != "" {
		err = fmt.Errorf("%w; core said: %s", err, last)
	}
	return checked, err
}

// The probe can complete just as an owned Aether process exits. Never accept
// the observed foreign IP alone as evidence of an *active* local transport.
func waitNativeWithProbe(ctx context.Context, mode string, n *nativeCore, probe func(context.Context, string, string) (observedExit, error)) (observedExit, error) {
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return observedExit{}, fmt.Errorf("native startup canceled or timed out; the selected method or verification endpoint may be unreachable (last check: %v): %w", lastErr, err)
		}
		select {
		case <-n.done:
			if n.err != nil {
				return observedExit{}, fmt.Errorf("Aether core exited before verification: %w", n.err)
			}
			return observedExit{}, errors.New("Aether core exited before verification")
		default:
		}
		checked, err := probe(ctx, mode, n.address)
		if err == nil {
			// A completed HTTPS exit check can race cancellation and a native
			// process exit. Both conditions must still be false at promotion.
			if ctx.Err() != nil {
				return observedExit{}, ctx.Err()
			}
			select {
			case <-n.done:
				if n.err != nil {
					return observedExit{}, fmt.Errorf("Aether core exited during verification: %w", n.err)
				}
				return observedExit{}, errors.New("Aether core exited during verification")
			default:
				return checked, nil
			}
		}
		lastErr = err
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
		case <-n.done:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// This explicit WARP carrier selector is TCP-only. Balanced separately keeps
// both direct and carried Psiphon/Tor profiles, including native UDP options.
func tcpCarriedProfiles(profiles []aether.Profile) []aether.Profile {
	var out []aether.Profile
	for _, p := range profiles {
		if aether.CanCarryLocally(p) {
			out = append(out, p)
		}
	}
	return out
}
