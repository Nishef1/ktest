package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
	"github.com/Nishef1/ktest/internal/connectionsession"
	"github.com/Nishef1/ktest/internal/exitnode"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

// Which way out works is a property of the network, not of the program: one
// operator drops QUIC, another lets only QUIC v2 through, another resets any
// ClientHello that names cloudflareclient.com, another blocks the WARP gateways
// altogether. Aether can do all of it, so ktest does not pick; it keeps a list
// of ways to run Aether (WARP over MASQUE on HTTP/2 or HTTP/3, WireGuard with
// obfuscation, over IPv6, and Psiphon, which does not depend on WARP at all),
// compares them two at a time and ranks successful neutral HTTPS measurements.
// A fresh per-network measurement orders the next live connection attempt.

func aetherProfilesFile(base string) string {
	return filepath.Join(base, "profiles", "aether-profiles.txt")
}

// loadAetherProfiles reads the editable list when it exists, else the default.
func loadAetherProfiles(base, ech, ip string, mode ConnectionMode) ([]aetherProfile, error) {
	text := defaultAetherProfiles
	if b, err := os.ReadFile(aetherProfilesFile(base)); err == nil {
		text = string(b)
	}
	profiles, err := parseAetherProfiles(text, ech, ip)
	if err != nil {
		return profiles, err
	}
	if mode == ModeBalanced || mode == ModeTor {
		hasTor := false
		for _, p := range profiles {
			hasTor = hasTor || p.Has("--tor-only")
		}
		if !hasTor {
			profiles = append(profiles, aetherProfile{Label: "Tor-only", Args: []string{"--tor-only"}})
		}
	}
	if mode == ModeFast || mode == ModeBalanced || mode == ModeAether {
		profiles = aether.WithLocalCarriers(aether.WithExitNodes(profiles))
	}
	return profilesForMode(profiles, mode), nil
}

// A first-use nested method must bootstrap its inner identity over an outer
// tunnel before the final carrier can even start. That work cannot fit inside
// the standard 45-second probe. Existing valid identities take the fast path.
func profileAttemptBudget(p aetherProfile) time.Duration {
	if p.Has("--tor-only") {
		return 7 * time.Minute
	}
	// Aether's own startup deadline precedes independent SOCKS/exit checks.
	budget := attemptTimeout(p) + 15*time.Second
	if budget < 45*time.Second {
		budget = 45 * time.Second
	}
	var protocol, path string
	switch p.Method() {
	case "gool-h2", "gool-h3":
		protocol, path = "wg", filepath.Join(warpDir(), "masque-gool.toml")
	case "wiw":
		protocol, path = "wg", filepath.Join(warpDir(), "wg-secondary.toml")
	case "mim-h2", "mim-h3":
		protocol, path = "masque", filepath.Join(warpDir(), "masque-secondary.toml")
	}
	if path != "" && os.IsNotExist(checkWarpIdentity(path, protocol)) && budget < 225*time.Second {
		// Outer core, inner enrollment, inner core; not one 45s attempt.
		return 225 * time.Second
	}
	return budget
}

// Each wave gives its first workers a complete native scan and tunnel startup.
// Later variants are retried in subsequent waves without inflating this one.
func (m *warpManager) searchBudget(indices []int) time.Duration {
	budget := 40 * time.Second
	workers := m.probeWorkers()
	if len(indices) > workers {
		indices = indices[:workers]
	}
	for _, i := range indices {
		if i < 0 || i >= len(m.profs) {
			continue
		}
		candidate := profileAttemptBudget(m.profs[i]) + 12*time.Second
		if candidate > budget {
			budget = candidate
		}
	}
	if budget > 8*time.Minute {
		budget = 8 * time.Minute
	}
	return budget
}

// aetherPorts: one fixed port per profile index, so a profile that is found
// again after a drop is the same upstream.
func aetherPort(i int) int { return aetherBasePort + i }

type warpManager struct {
	o             connectOptions
	proxy         *smartproxy.Proxy
	t             *term
	profs         []aetherProfile
	monitor       *windscribeMonitor
	searching     atomic.Bool
	enrollMu      sync.Mutex
	enrollTried   map[string]bool
	enrollRoutes  []enrollmentRoute
	ech, echIP    string
	network, core string
	processCtx    context.Context
	measureMu     sync.Mutex
	measurements  []aetherMeasurement
	diagnosis     bool
	selected      *aetherMeasurement
	attempted     map[string]bool
	failedSweeps  int
	carrierMu     sync.Mutex
	carrier       *connectionsession.Session
	exitNodes     map[string]*exitnode.Server
	keyMu         sync.Mutex
	keyChecked    bool // the saved MASQUE key was put to a gateway this connection
	psiphonEdges  []string
}

// exitNode starts, once per preset, PattNG's loopback exit-node: the masked
// freedom outbound every core of that preset dials out through.
func (m *warpManager) exitNode(ctx context.Context, preset string) (string, error) {
	m.carrierMu.Lock()
	defer m.carrierMu.Unlock()
	if s := m.exitNodes[preset]; s != nil {
		return s.Addr(), nil
	}
	mask, err := exitnode.Preset(preset)
	if err != nil {
		return "", err
	}
	owner := m.processCtx
	if owner == nil {
		owner = ctx
	}
	s, err := exitnode.Start(owner, "127.0.0.1:0", mask)
	if err != nil {
		return "", err
	}
	if m.exitNodes == nil {
		m.exitNodes = map[string]*exitnode.Server{}
	}
	m.exitNodes[preset] = s
	return s.Addr(), nil
}

func (m *warpManager) stopExitNodes() {
	m.carrierMu.Lock()
	defer m.carrierMu.Unlock()
	for preset, s := range m.exitNodes {
		s.Stop()
		delete(m.exitNodes, preset)
	}
}

func (m *warpManager) localCarrier(ctx context.Context) (string, error) {
	m.carrierMu.Lock()
	defer m.carrierMu.Unlock()
	if m.carrier == nil {
		owner := m.processCtx
		if owner == nil {
			owner = ctx
		}
		source := m.proxy
		if m.o.carrierSource != nil {
			source = m.o.carrierSource
		}
		var err error
		m.carrier, err = connectionsession.StartLocalCarrier(owner, source)
		if err != nil {
			return "", err
		}
	}
	return m.carrier.SOCKS.Addr().String(), nil
}

func (m *warpManager) status() string {
	total, verified := m.proxy.ExitCounts()
	phase := "retry pending"
	if m.searching.Load() {
		phase = "search continuing"
	} else if total > 0 {
		phase = "active"
	}
	// One short line: it sits inside the status panel.
	status := fmt.Sprintf("%d %s · %s", total, plural(total, "exit", "exits"), phase)
	if verified > 0 {
		status += fmt.Sprintf(" · %d outside Iran", verified)
	}
	m.measureMu.Lock()
	defer m.measureMu.Unlock()
	if m.selected != nil {
		r := m.selected
		status += fmt.Sprintf(" · %s · %s %s", r.Method, r.ExitIP, r.Country)
	}
	return status
}

// startWarp runs the search for a working exit in the background and returns
// the note for the result box and the function that stops everything.
func startWarp(ctx context.Context, o connectOptions, proxy *smartproxy.Proxy, t *term, monitors ...*windscribeMonitor) (func() string, func()) {
	fixed := func(note string) (func() string, func()) { return func() string { return note }, func() {} }
	if o.mode == ModeWindscribe {
		// Safety boundary: even accidental calls must not launch Aether,
		// Psiphon, WARP or a foreign proxy in Windscribe mode.
		return fixed("prohibited (Windscribe local-only mode)")
	}
	if o.noWarp {
		return fixed("managed exit search off (-no-warp)")
	}
	if warpState(o.base) == "no core" {
		return fixed("off - `ktest warp -enable` adds WARP/Psiphon exits")
	}
	if o.mode == ModePsiphon && !fileOK(psiphonCore(o.base)) {
		return fixed("Psiphon unavailable: helper missing; `ktest warp -enable` fetches it")
	}
	m, err := newWarpManager(ctx, o, proxy, t, false)
	if err != nil {
		return fixed("off - " + err.Error())
	}
	if len(monitors) > 0 {
		m.monitor = monitors[0]
	}
	if o.mode == ModePsiphon {
		m.psiphonEdges = supportedPsiphonEdges(ctx, aetherBinary(o.base))
	}
	t.Note("Aether v2.3.1 stores WARP keys privately; a listener is not a verified foreign exit. KTest separately verifies outbound HTTPS.")
	m.searching.Store(true)
	mctx, stopManager := context.WithCancel(ctx)
	m.processCtx = mctx
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.run(mctx)
	}()
	return m.status, func() {
		stopManager()
		<-done
	}
}

// maxExits is how many tunnels are kept open at once.
const maxExits = 3

// PattNG refuses a scan that shares a live session's WARP identity. Strict
// WARP modes likewise scan one profile at a time and keep its verified winner,
// rather than probing/replenishing variants with the same device keys beside it.
func (m *warpManager) probeWorkers() int {
	if m.o.mode == ModeAether || m.o.mode == ModeWindscribeAether {
		return 1
	}
	if m.o.mode == ModeBalanced {
		return 3
	}
	return 2
}

func (m *warpManager) capacity() int {
	if m.o.mode == ModeBalanced || m.o.mode == ModeFast || m.o.mode == ModeAether || m.o.mode == ModeWindscribeAether {
		return 1
	}
	return maxExits
}

// run keeps established foreign TCP transports alive when Windscribe reports
// Connected; killing one would also kill an OpenVPN session using that path.
// Dead transports are removed immediately rather than advertised as healthy.
func (m *warpManager) run(ctx context.Context) {
	// Keep established transports alive while replenishing spare capacity.
	// A port is tied to a stable profile index, never a reordered search rank.
	active := make(map[string]*warpFound)
	ended := make(chan *warpFound, maxExits)
	stopAll := func() {
		for _, w := range active {
			w.rc.stop()
		}
		for _, w := range active {
			if w.unregistered != nil {
				<-w.unregistered
			}
		}
		if m.carrier != nil {
			m.carrier.Stop()
		}
	}
	retire := func(w *warpFound) {
		id := w.p.ID()
		if current, ok := active[id]; !ok || current != w {
			return
		}
		w.rc.stop()
		if w.unregistered != nil {
			<-w.unregistered
		}
		delete(active, id)
		// The profile that was working is retried first (with its cached
		// gateway), before a scan of other variants.
		delete(m.attempted, id)
		m.t.Line(toneWarn, "%s ended; replenishing available exit capacity", w.p.Label)
	}
	defer stopAll()
	for ctx.Err() == nil {
		// Do not disrupt an authenticated Windscribe session with new scans.
		// Continue processing dead-core events even while discovery is paused.
		if m.monitor != nil && m.monitor.Connected() {
			select {
			case <-ctx.Done():
				return
			case w := <-ended:
				retire(w)
			case <-time.After(2 * time.Second):
			}
			continue
		}
		if len(active) < m.capacity() {
			m.searching.Store(true)
			found := m.search(ctx, active)
			m.searching.Store(false)
			for _, w := range found {
				active[w.p.ID()] = w
				go func(w *warpFound) {
					select {
					case <-ctx.Done():
					case <-w.rc.done:
						select {
						case ended <- w:
						case <-ctx.Done():
						}
					}
				}(w)
			}
			if len(found) > 0 {
				m.resetRecovery()
				// Live exits are excluded from the next recovery attempt.
				if m.attempted == nil {
					m.attempted = make(map[string]bool)
				}
				for id := range active {
					m.attempted[id] = true
				}
			}
			if ctx.Err() == nil {
				m.t.Note("Exit status: %s", m.status())
			}
		}
		if ctx.Err() != nil {
			return
		}
		// When capacity is full, wait for the first failure. When partially
		// available, back off before probing for another independent exit.
		delay := m.recoveryDelay()
		if len(active) >= min(m.capacity(), len(m.profs)) {
			delay = 0
		} else if len(active) == 0 {
			m.t.Line(toneWarn, "No permitted exit verified; retrying discovery in %s (%d compatible profiles). Saved identities are kept.", delay, len(m.profs))
		} else {
			m.t.Note("%d/%d exits active; checking alternatives in %s", len(active), m.capacity(), delay)
		}
		var retry <-chan time.Time
		var timer *time.Timer
		if delay > 0 {
			timer = time.NewTimer(delay)
			retry = timer.C
		}
		select {
		case <-ctx.Done():
		case w := <-ended:
			retire(w)
		case <-retry:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

// Deregister a dead exit immediately, even while other profiles are still
// being searched. Waiting for search to finish could advertise a dead core.
func (m *warpManager) watchExit(ctx context.Context, name string, rc *runningCore) {
	select {
	case <-ctx.Done():
	case <-rc.done:
	}
	m.proxy.Remove("Exit: " + name)
	m.measureMu.Lock()
	if m.selected != nil && m.selected.Label == name {
		m.selected = nil
	}
	m.measureMu.Unlock()
	if ctx.Err() == nil {
		m.t.Line(toneWarn, "%s ended; no longer eligible for new connections", name)
		m.t.Note("Exit status: %s", m.status())
	}
}

type warpFound struct {
	p            aetherProfile
	port         int
	rc           *runningCore
	unregistered chan struct{}
}

// orderedCandidateIndices ranks measurements without mutating m.profs:
// active Aether processes already own their original index-derived ports.
func (m *warpManager) orderedCandidateIndices(active map[string]*warpFound, history networkProfile) []int {
	byID := make(map[string]int, len(m.profs))
	for i, p := range m.profs {
		byID[p.ID()] = i
	}
	var indices []int
	for _, p := range recoveryProfilesFirst(m.profs, history, m.o.mode) {
		if _, inUse := active[p.ID()]; inUse || m.attempted[p.ID()] {
			continue
		}
		indices = append(indices, byID[p.ID()])
	}
	return indices
}

// Compare before exposing the initial choice. A cached winner gets one worker;
// first-use discovery has a shared deadline rather than delaying the UI for minutes.
func (m *warpManager) search(ctx context.Context, active map[string]*warpFound) []*warpFound {
	limit := m.capacity() - len(active)
	if limit <= 0 {
		return nil
	}
	history, _ := cachedNetwork(m.network, m.core)
	indices := m.orderedCandidateIndices(active, history)
	if len(indices) == 0 {
		// Every inactive candidate had a turn. Revisit failures without
		// touching already-running ports or their pinned sessions.
		m.attempted = nil
		indices = m.orderedCandidateIndices(active, history)
	}
	if len(indices) == 0 {
		return nil // nil means the entire inventory to compare, not zero candidates.
	}
	if m.o.mode == ModeAether || m.o.mode == ModeWindscribeAether {
		indices = indices[:1] // the next variant gets a fresh wave after this core stops
	}
	if len(active) == 0 && len(indices) > 0 {
		first := m.profs[indices[0]]
		if r, ok := history.Results[first.ID()]; ok && (r.State == "verified" || m.o.mode == ModeWindscribeAether) && measurementScore(r, m.o.mode) < 1e12 && time.Since(r.Checked) < networkCacheTTL {
			limit = 1
		}
	}
	searchCtx, stopSearch := context.WithTimeout(ctx, m.searchBudget(indices))
	results := m.compare(searchCtx, limit, false, indices)
	stopSearch()
	var found []*warpFound
	for i, r := range results {
		select {
		case <-r.rc.done:
			r.rc.stop()
			continue
		default:
		}
		err := m.proxy.Add(smartproxy.Upstream{Name: "Exit: " + r.p.Label, Addr: fmt.Sprintf("127.0.0.1:%d", r.port), Rank: 5 + i, Exit: true, AIEligible: r.result.State == "verified", Late: !m.o.mode.exitOnly()})
		if err != nil {
			r.rc.stop()
			continue
		}
		found = append(found, r.warpFound)
		if len(found) == 1 {
			m.measureMu.Lock()
			sample := r.result
			m.selected = &sample
			m.measureMu.Unlock()
		}
		r.unregistered = make(chan struct{})
		go func(w *warpFound) {
			defer close(w.unregistered)
			m.watchExit(ctx, w.p.Label, w.rc)
		}(r.warpFound)
		go m.watchHealth(ctx, r.warpFound)
		m.t.Line(toneOK, "Exit selected: %s · %s", r.p.Label, r.result.detail())
		m.t.Note("Observed exit belongs to the neutral probe, not a permanent per-website IP guarantee.")
	}
	return found
}

// try starts one profile and waits for its proxy port. On success the process
// keeps running; on failure it is stopped.
func (m *warpManager) try(ctx context.Context, i int, p aetherProfile) (bool, *runningCore, string) {
	if !p.Psiphon() {
		if err := m.prepareIdentity(ctx, p); err != nil {
			if ctx.Err() == nil {
				m.t.Note("%s skipped: %v", p.Label, err)
			}
			if ctx.Err() != nil {
				return false, nil, "identity bootstrap cancelled or timed out"
			}
			return false, nil, "identity bootstrap unavailable (see diagnostic)"
		}
	}
	return m.startProfile(ctx, i, p)
}

func (m *warpManager) startProfile(ctx context.Context, i int, p aetherProfile) (bool, *runningCore, string) {
	port := aetherPort(i)
	if err := portFree(port); err != nil {
		m.t.Note("skipped %s: %v", p.Label, err)
		return false, nil, "local SOCKS port occupied"
	}
	readyCtx, cancelReady := context.WithCancel(ctx)
	defer cancelReady()
	logs := &tailBuffer{max: 8192}
	progress := &aetherProgress{show: func(stage string) { m.t.Note("%s: %s", p.Label, stage) }}
	if m.automaticWARPDiscovery() && (p.Method() == "masque-h2" || p.Method() == "masque-h3") && !p.Has("--peer") {
		// A completed failed scan is a scheduling result. Don't spend the
		// remaining startup allowance repeating it before other methods run.
		// Only readiness is cancelled: a selected core owns the session context.
		progress.scanFailed = cancelReady
	}
	logPath := filepath.Join(warpDir(), fmt.Sprintf("aether-%d.log", i+1))
	var sinks []io.Writer
	var logFile *os.File
	if lf, err := os.Create(logPath); err == nil {
		logFile = lf
		sinks = append(sinks, lf)
	}
	if m.o.verbose {
		sinks = append(sinks, os.Stderr)
	}
	if len(sinks) > 0 {
		logs.tee = io.MultiWriter(sinks...)
	}
	processCtx := m.processCtx
	if processCtx == nil {
		processCtx = ctx
	}
	cctx, cancel := context.WithCancel(processCtx)
	rc := &runningCore{cancel: cancel, done: make(chan struct{})}
	args := aetherRunArgs(i, p, port)
	if preset := p.ExitNode(); preset != "" {
		address, err := m.exitNode(ctx, preset)
		if err == nil {
			args, err = aether.BindLocalCarrier(args, address)
		}
		if err != nil {
			cancel()
			if logFile != nil {
				logFile.Close()
			}
			return false, nil, "PattNG exit-node unavailable"
		}
	} else if p.LocalCarrier() {
		address, err := m.localCarrier(ctx)
		if err != nil {
			cancel()
			if logFile != nil {
				logFile.Close()
			}
			return false, nil, "local anti-DPI carrier unavailable"
		}
		args, err = aether.BindLocalCarrier(args, address)
		if err != nil {
			cancel()
			if logFile != nil {
				logFile.Close()
			}
			return false, nil, "invalid local anti-DPI carrier"
		}
	} else if m.o.carrierSource != nil && carriesExit(p) {
		// Psiphon/Tor own their exit; the carrier only shapes how they leave
		// Iran. Without it they still try their own transports directly.
		address, err := m.localCarrier(ctx)
		if err == nil {
			args, err = withCarrier(args, address)
		}
		if err != nil {
			args = aetherRunArgs(i, p, port)
			m.t.Note("%s: local anti-DPI carrier unavailable (%v); dialing directly", p.Label, err)
		}
	}
	args = withPsiphonEdges(args, p, m.psiphonEdges)
	go func() {
		defer close(rc.done)
		if logFile != nil {
			defer logFile.Close()
		}
		rc.err = aether.Run(cctx, aetherBinary(m.o.base), args, io.MultiWriter(logs, progress))
	}()
	// Once the VPN is back, unfinished discovery attempts must stop. Do not
	// cancel a transport that has already passed try() and is carrying the VPN.
	if m.monitor != nil {
		watchEnd := make(chan struct{})
		defer close(watchEnd)
		go func() {
			tick := time.NewTicker(2 * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-watchEnd:
					return
				case <-cctx.Done():
					return
				case <-tick.C:
					if m.monitor.Connected() {
						rc.cancel()
						return
					}
				}
			}
		}()
	}
	deadline := time.Now().Add(attemptTimeout(p))
	ready := waitForPort(readyCtx, rc.done, port, time.Until(deadline))
	if ready && exitCarries(readyCtx, rc.done, port, time.Until(deadline)) {
		return true, rc, ""
	}
	reason := "gateway scan/startup budget expired before SOCKS readiness; discovery incomplete"
	switch {
	case ctx.Err() != nil:
		reason = "attempt cancelled or timed out"
	case readyCtx.Err() != nil:
		reason = "native gateway scan finished without a usable gateway; trying another profile (remaining candidates are untested)"
	case ready:
		reason = "SOCKS opened but upstream TLS carrier did not verify"
	default:
		select {
		case <-rc.done:
			reason = "Aether process exited before SOCKS readiness"
		default:
		}
	}
	rc.cancel()
	rc.stop()
	if stage := progress.stage(); stage != "" {
		reason += "; last stage: " + stage
	}
	if ctx.Err() == nil {
		m.t.Note("%s: %s (local core log: %s)", p.Label, reason, logPath)
	}
	return false, nil, reason
}

// Profile workers share enrollment. A failed API bootstrap is attempted once
// per protocol per connection, not once for every H2/H3/obfuscation profile
// on every two-minute tunnel retry. Setup offers an explicit retry.
// readyIdentity checks only local credentials; it does not claim a live tunnel.
// A worker with existing identities must not wait for another worker's slow,
// unrelated enrollment, or "two profiles at once" degenerates into one.
func readyIdentity(p aetherProfile) bool { return aether.ReadyIdentity(p, warpDir()) }

func (m *warpManager) prepareIdentity(ctx context.Context, p aetherProfile) error {
	if p.Psiphon() || p.Has("--tor-only") {
		return nil // standalone carriers have no WARP enrollment requirement
	}
	m.checkMasqueKey(ctx, p)
	if readyIdentity(p) {
		return ctx.Err()
	}
	m.enrollMu.Lock()
	defer m.enrollMu.Unlock()
	if m.enrollTried == nil {
		m.enrollTried = make(map[string]bool)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	protocol, path := "masque", identityFile()
	if p.Method() == "wireguard" || p.Method() == "wiw" {
		protocol, path = "wg", wireguardIdentityFile()
	}
	if err := m.prepareIdentityFile(ctx, protocol, path, nil); err != nil {
		return err
	}
	switch {
	case p.Method() == "wiw":
		return m.prepareIdentityFile(ctx, "wg", filepath.Join(warpDir(), "wg-secondary.toml"), nil)
	case strings.HasPrefix(p.Method(), "mim-"):
		return m.prepareIdentityFile(ctx, "masque", filepath.Join(warpDir(), "masque-secondary.toml"), nil)
	case strings.HasPrefix(p.Method(), "gool-"):
		inner := filepath.Join(warpDir(), "masque-gool.toml")
		if err := checkWarpIdentity(inner, "wg"); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		if m.enrollTried[inner] {
			return fmt.Errorf("Gool inner enrollment already attempted this connection; retry diagnosis or reconnect")
		}
		outer := aether.GoolOuterProfile(p)
		up, rc, reason := m.startProfile(ctx, 80, outer)
		if !up {
			// Cancellation is not evidence of a bad identity. Permit a fresh
			// attempt after recovery/reconnect rather than poisoning this session.
			if err := ctx.Err(); err != nil {
				return err
			}
			m.enrollTried[inner] = true
			return fmt.Errorf("outer MASQUE tunnel unavailable (%s); inner registration not attempted; saved keys kept", reason)
		}
		defer rc.stop()
		routes := []enrollmentRoute{{label: "outer MASQUE tunnel", args: []string{"--upstream", fmt.Sprintf("socks5://127.0.0.1:%d", aetherPort(80))}}}
		return m.prepareIdentityFile(ctx, "wg", inner, routes)
	}
	return nil
}

// checkMasqueKey asks a gateway, once per connection, whether the saved
// MASQUE key is still accepted. A key can be intact on disk and dead at
// Cloudflare (CONNECT-IP 400 / certificate refused at every gateway); it then
// never connects, and enrollment never ran because the file looked valid.
// A refused key is set aside, never deleted, so a fresh one is registered.
func (m *warpManager) checkMasqueKey(ctx context.Context, p aetherProfile) {
	method := p.Method()
	if p.Psiphon() || p.Has("--tor-only") || method == "wireguard" || method == "wiw" {
		return
	}
	// Its own lock: a ready worker must not wait behind a slow enrollment.
	m.keyMu.Lock()
	defer m.keyMu.Unlock()
	if m.keyChecked || checkWarpIdentity(identityFile(), "masque") != nil {
		return
	}
	m.keyChecked = true
	probeCtx := ctx
	if !m.diagnosis {
		// This optional preflight must not spend up to six 20-second peer
		// timeouts before the real carrier attempt even starts. An inconclusive
		// check preserves the key; live tunnel/HTTPS validation remains required.
		var cancel context.CancelFunc
		probeCtx, cancel = context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		if m.t != nil {
			m.t.Note("Checking the saved WARP key (up to 8s); live carrier search follows")
		}
	}
	verdict, err := aether.ProbeMasqueIdentity(probeCtx, aetherBinary(m.o.base), identityFile())
	if err != nil && ctx.Err() == nil && m.t != nil {
		m.t.Note("Saved WARP key check inconclusive; keeping the key and trying the live carrier")
	}
	if err != nil || verdict != aether.IdentityRejected {
		return
	}
	backup, err := aether.SetAsideRejectedIdentity(identityFile())
	if err != nil {
		m.t.Line(toneWarn, "WARP refused the saved MASQUE key, and it could not be set aside: %v", err)
		return
	}
	m.t.Line(toneWarn, "WARP refused the saved MASQUE key; registering a new one (old key kept as %s)", filepath.Base(backup))
}

// A listening local SOCKS port is not a functioning foreign exit. Strict
// Aether bootstrap must not try to register through its own empty proxy.
func canUseEnrollmentProxy(mode ConnectionMode, proxy *smartproxy.Proxy) bool {
	return !mode.exitOnly() || (proxy != nil && proxy.HasVerifiedExit())
}

// Called with enrollMu held. Inner files have their own attempt ledger.
func (m *warpManager) prepareIdentityFile(ctx context.Context, protocol, path string, routes []enrollmentRoute) error {
	if err := checkWarpIdentity(path, protocol); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	key := path
	if path == identityFile() || path == wireguardIdentityFile() {
		key = protocol
	}
	if m.enrollTried[key] {
		return fmt.Errorf("%s identity unavailable; retry Setup > Exit paths (automatic registration already attempted this connection)", protocol)
	}
	if m.enrollTried == nil {
		m.enrollTried = make(map[string]bool)
	}
	m.enrollTried[key] = true
	if routes == nil && m.enrollRoutes == nil {
		proxyAddr := ""
		if m.o.mode == ModeFast || m.o.mode == ModeBalanced || m.o.mode == ModeAether {
			var err error
			proxyAddr, err = m.localCarrier(ctx)
			if err != nil {
				return err
			}
		} else if canUseEnrollmentProxy(m.o.mode, m.proxy) {
			proxyAddr = m.o.listen
		}
		m.enrollRoutes = enrollmentRoutes(ctx, m.o.base, proxyAddr, m.ech, m.echIP)
		if m.o.mode == ModeFast || m.o.mode == ModeBalanced || m.o.mode == ModeAether {
			// PattNG sends the WARP API registration through the same
			// exit-node as the tunnel. Where the API name is filtered by a
			// reassembling DPI that does not help, so ECH stays first.
			if node, err := m.exitNode(ctx, aether.ExitNodePreset("masque-h2")); err == nil {
				at := 0
				if len(m.enrollRoutes) > 0 && m.enrollRoutes[0].label == "ECH" {
					at = 1
				}
				node := enrollmentRoute{"PattNG exit-node", []string{"--upstream", "socks5://" + node}}
				m.enrollRoutes = append(m.enrollRoutes[:at], append([]enrollmentRoute{node}, m.enrollRoutes[at:]...)...)
			}
		}
		if m.o.mode == ModeFast {
			m.enrollRoutes = fastEnrollmentRoutes(m.enrollRoutes)
		}
	}
	if routes == nil {
		routes = m.enrollRoutes
	}
	return enrollWarpIdentityAt(ctx, m.t, aetherBinary(m.o.base), protocol, path, routes, runEnrollment)
}

// exitCarries waits until a request really goes through the proxy on port. The
// port opens before some cores (Psiphon) have a tunnel, so an open port proves
// nothing: a TLS handshake with a Cloudflare name must complete through it.
func exitCarries(ctx context.Context, done <-chan struct{}, port int, limit time.Duration) bool {
	end := time.Now().Add(limit)
	for time.Now().Before(end) {
		select {
		case <-ctx.Done():
			return false
		case <-done:
			return false
		default:
		}
		hctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		c, err := smartproxy.DialVia(hctx, fmt.Sprintf("127.0.0.1:%d", port), "www.cloudflare.com", "443", 8*time.Second)
		if err == nil {
			tc := tls.Client(c, &tls.Config{ServerName: "www.cloudflare.com"})
			_ = c.SetDeadline(time.Now().Add(8 * time.Second))
			err = tc.HandshakeContext(hctx)
			_ = tc.Close()
		}
		cancel()
		if err == nil {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(2 * time.Second):
		}
	}
	return false
}
