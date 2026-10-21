package mobilebridge

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
	"github.com/Nishef1/ktest/internal/connectionsession"
	"github.com/Nishef1/ktest/internal/exitnode"
	"github.com/Nishef1/ktest/internal/front"
	"github.com/Nishef1/ktest/internal/smartproxy"
	"github.com/Nishef1/ktest/internal/tlsshape"
)

// An automatic exit belongs to the Go connection session, not an Activity or
// a caller waiting for its first request. It keeps a working core and retries
// other compatible methods after failure without blocking local connections.
type automaticExit struct {
	ctx        context.Context
	cancel     context.CancelFunc
	once       sync.Once
	done       chan struct{}
	mode       string
	options    nativeOptions
	proxy      *smartproxy.Proxy
	historyKey string
	mu         sync.Mutex
	current    *nativeCore
	location   string
	attempt    func(context.Context, aether.Profile) (*nativeCore, observedExit, error)
	carrierMu  sync.Mutex
	carrier    *connectionsession.Session
	exitNodes  map[string]*exitnode.Server
	enrollMu   sync.Mutex // serialize only cold first-use WARP identity provisioning
}

func shouldWarmAutomaticExit(mode string) bool { return mode == "balanced" }

type nativeHint struct {
	Key     string    `json:"key"`
	ID      string    `json:"id"`
	Checked time.Time `json:"checked"`
}

func mobileHistory(mode, dir string) (string, string) {
	network := currentRouteNetworkToken()
	if dir == "" || network == "" {
		return "", ""
	}
	sum := sha256.Sum256([]byte(network + "/" + mode))
	key := hex.EncodeToString(sum[:])
	return filepath.Join(dir, "routes-"+key+".json"), key
}

func newAutomaticExit(mode, libraryDir, stateDir, key string) *automaticExit {
	ctx, cancel := context.WithCancel(context.Background())
	a := &automaticExit{ctx: ctx, cancel: cancel, done: make(chan struct{}), mode: mode, historyKey: key,
		// privateDir lets Psiphon's CDN fronting try this network's verified edges.
		options: nativeOptions{libraryDir: libraryDir, stateDir: filepath.Join(stateDir, "aether"), privateDir: stateDir}}
	a.attempt = func(ctx context.Context, p aether.Profile) (*nativeCore, observedExit, error) {
		o, err := a.optionsForProfile(p)
		if err != nil {
			return nil, observedExit{}, err
		}
		// Shared WARP key files must not be concurrently provisioned
		// on a cold start. Already-valid profiles retain parallel probing.
		releaseEnrollment := a.lockColdIdentity(p, o.stateDir)
		defer releaseEnrollment()
		n, err := launchNative(ctx, mode, o)
		if err != nil {
			return nil, observedExit{}, err
		}
		stop := context.AfterFunc(ctx, n.cancel)
		verifyMode := mode
		if p.Has("--tor-only") {
			verifyMode = "tor"
		}
		checked, err := waitNative(ctx, verifyMode, n)
		if !stop() && err == nil {
			err = ctx.Err()
		}
		if err != nil {
			n.stop()
			return nil, observedExit{}, err
		}
		return n, checked, nil
	}
	return a
}

// lockColdIdentity protects a first-time enrollment against other Balanced
// workers sharing the same state directory. Recheck after taking the lock:
// another worker may already have saved a complete identity while we waited.
// A direct Aether Auto uses sequential starts; Psiphon and Tor bypass the lock.
// The selected process owns its registration lifecycle until the attempt ends.
func (a *automaticExit) lockColdIdentity(p aether.Profile, dir string) func() {
	if len(aether.IdentityRequirements(p)) == 0 || aether.ReadyIdentity(p, dir) {
		return func() {}
	}
	a.enrollMu.Lock()
	if aether.ReadyIdentity(p, dir) {
		a.enrollMu.Unlock()
		return func() {}
	}
	return a.enrollMu.Unlock
}

// The carrier variant is independent of direct startup. In particular,
// sending Psiphon through SOCKS disables its native QUIC transports, so never
// silently replace the direct profile with a carried one.
func (a *automaticExit) optionsForProfile(p aether.Profile) (nativeOptions, error) {
	o := a.options
	// Earlier Balanced/Fast used automatic-exits while standalone Aether
	// used aether. Both now share only validated identities in aether/.
	// Never discard or overwrite an existing valid saved key.
	legacy := filepath.Join(o.privateDir, "automatic-exits")
	if _, err := aether.MigrateIdentityFiles(o.stateDir, legacy); err != nil {
		return o, fmt.Errorf("reconcile previous Android identities: %w", err)
	}
	o.profile = &p
	if preset := p.ExitNode(); preset != "" {
		address, err := a.exitNode(preset)
		if err != nil {
			return o, err
		}
		o.carrier = address
	} else if p.LocalCarrier() {
		address, err := a.localCarrier()
		if err != nil {
			return o, err
		}
		o.carrier = address
	}
	return o, nil
}

// exitNode starts PattNG's loopback exit-node for a finalMask preset once.
func (a *automaticExit) exitNode(preset string) (string, error) {
	a.carrierMu.Lock()
	defer a.carrierMu.Unlock()
	if s := a.exitNodes[preset]; s != nil {
		return s.Addr(), nil
	}
	mask, err := exitnode.Preset(preset)
	if err != nil {
		return "", err
	}
	s, err := exitnode.Start(a.ctx, "127.0.0.1:0", mask)
	if err != nil {
		return "", err
	}
	if a.exitNodes == nil {
		a.exitNodes = map[string]*exitnode.Server{}
	}
	a.exitNodes[preset] = s
	return s.Addr(), nil
}

func (a *automaticExit) localCarrier() (string, error) {
	a.carrierMu.Lock()
	defer a.carrierMu.Unlock()
	if a.carrier == nil {
		var err error
		a.carrier, err = connectionsession.StartLocalCarrier(a.ctx, a.proxy)
		if err != nil {
			return "", err
		}
	}
	return a.carrier.SOCKS.Addr().String(), nil
}

func (a *automaticExit) ensure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.ctx.Err() != nil {
		return a.ctx.Err()
	}
	a.once.Do(func() { go func() { defer close(a.done); a.run() }() })
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if a.proxy.HasVerifiedExit() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-a.ctx.Done():
			return a.ctx.Err()
		case <-tick.C:
		}
	}
}

func (a *automaticExit) stop() { a.cancel(); a.once.Do(func() { close(a.done) }); <-a.done }

func (a *automaticExit) snapshot() (string, string, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current == nil {
		return "", "", ""
	}
	return a.current.address, a.current.method, a.location
}

func (a *automaticExit) hintFile() string {
	return filepath.Join(a.options.stateDir, "preferred-"+a.historyKey+".json")
}

func (a *automaticExit) profiles() []aether.Profile {
	ech, ip := "", ""
	ctx, stop := context.WithTimeout(a.ctx, 3*time.Second)
	if config, edge, err := front.SharedCloudflareECH(ctx); err == nil {
		ech, ip = base64.StdEncoding.EncodeToString(config), edge
	}
	stop()
	profiles, _ := aether.ParseProfiles(aether.DefaultProfiles, ech, ip)
	profiles = aether.ProfilesForMode(profiles, a.mode)
	if a.mode == "balanced" {
		profiles = append(profiles, aether.Profile{Label: "Tor-only", Args: []string{"--tor-only"}})
	}
	shape, measured := mobileTLSShape(a.ctx, a.options.privateDir, a.mode != "psiphon" && a.mode != "tor")
	profiles = aether.WithLocalCarriers(aether.WithExitNodes(shapeProfiles(profiles, shape, measured)))
	profiles = tlsshape.Order(profiles, measured)
	var hint nativeHint
	if raw, err := os.ReadFile(a.hintFile()); err == nil && len(raw) < 4096 && json.Unmarshal(raw, &hint) == nil && hint.Key == a.historyKey && hint.Key != "" && time.Since(hint.Checked) < 24*time.Hour && time.Until(hint.Checked) < time.Minute {
		sort.SliceStable(profiles, func(i, j int) bool { return profiles[i].ID() == hint.ID && profiles[j].ID() != hint.ID })
	}
	return profiles
}

type nativeResult struct {
	core    *nativeCore
	checked observedExit
	profile aether.Profile
}

func (a *automaticExit) discover(profiles []aether.Profile) *nativeResult {
	profiles = aether.IndependentProfilesFirst(profiles)
	ctx, cancel := context.WithCancel(a.ctx)
	defer cancel()
	results := make(chan nativeResult, 2)
	var mu sync.Mutex
	var workers sync.WaitGroup
	next := 0
	count := 2
	if a.mode == "balanced" {
		count = 3 // WARP, Psiphon and Tor must be able to bootstrap independently.
	}
	for worker := range count {
		workers.Go(func() {
			if worker > 0 {
				timer := time.NewTimer(time.Duration(worker) * 200 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
				}
			}
			for ctx.Err() == nil {
				mu.Lock()
				i := next
				next++
				mu.Unlock()
				if i >= len(profiles) {
					return
				}
				p := profiles[i]
				budget := aether.AttemptTimeout(p) + 15*time.Second
				if p.Has("--tor-only") {
					budget = 7 * time.Minute
				}
				attempt, stop := context.WithTimeout(ctx, budget)
				n, checked, err := a.attempt(attempt, p)
				stop()
				if err != nil {
					continue
				}
				select {
				case results <- nativeResult{n, checked, p}:
				case <-ctx.Done():
					n.stop()
				}
				return
			}
		})
	}
	finished := make(chan struct{})
	go func() { workers.Wait(); close(results); close(finished) }()
	var selected *nativeResult
	for r := range results {
		if selected == nil && a.ctx.Err() == nil {
			selected = &r
			cancel()
		} else {
			r.core.stop()
		}
	}
	<-finished
	return selected
}

func (a *automaticExit) run() {
	defer func() {
		if a.carrier != nil {
			a.carrier.Stop()
		}
		a.carrierMu.Lock()
		for _, s := range a.exitNodes {
			s.Stop()
		}
		a.exitNodes = nil
		a.carrierMu.Unlock()
	}()
	profiles := a.profiles()
	lastWorking := ""
	// Each recovery round rebuilds the list: the ECH key fetched at session
	// start may have failed or been rotated, and the network may have
	// changed. The last working transport stays first.
	refresh := func() {
		if a.ctx.Err() != nil {
			return
		}
		profiles = a.profiles()
		if lastWorking != "" {
			sort.SliceStable(profiles, func(i, j int) bool { return profiles[i].ID() == lastWorking && profiles[j].ID() != lastWorking })
		}
	}
	for a.ctx.Err() == nil {
		r := a.discover(profiles)
		if r == nil {
			timer := time.NewTimer(30 * time.Second)
			select {
			case <-a.ctx.Done():
			case <-timer.C:
			}
			timer.Stop()
			refresh()
			continue
		}
		name := "Exit: " + r.profile.Label
		if err := a.proxy.Add(smartproxy.Upstream{Name: name, Addr: r.core.address, Exit: true, AIEligible: true, Late: true, Rank: 9}); err != nil {
			r.core.stop()
			continue
		}
		a.mu.Lock()
		a.current, a.location = r.core, r.checked.Region
		a.mu.Unlock()
		if a.historyKey != "" {
			raw, _ := json.Marshal(nativeHint{a.historyKey, r.profile.ID(), time.Now()})
			_ = os.MkdirAll(a.options.stateDir, 0700)
			_ = os.WriteFile(a.hintFile(), raw, 0600)
		}
		a.watch(r.core)
		a.proxy.Remove(name)
		a.mu.Lock()
		a.current = nil
		a.location = ""
		a.mu.Unlock()
		r.core.stop()
		// Retry the last working transport first, then every other method.
		lastWorking = r.profile.ID()
		refresh()
	}
}

func (a *automaticExit) watch(n *nativeCore) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	failures := 0
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-n.done:
			return
		case <-tick.C:
			ctx, stop := context.WithTimeout(a.ctx, 10*time.Second)
			_, err := verifyModeUpstream(ctx, a.mode, n.address)
			stop()
			if err != nil {
				failures++
			} else {
				failures = 0
			}
			if failures >= 2 || errors.Is(err, context.Canceled) {
				return
			}
		}
	}
}
