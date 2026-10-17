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

	"github.com/Nishef1/ktest/internal/dnscheck"
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

// defaultAetherProfiles is the shipped list; profiles/aether-profiles.txt
// replaces it. {ECH} and {ECHIP} are an ECH configuration and a Cloudflare edge
// address that ktest fetched itself, with no DNS: they make the calls to the
// WARP API (the key) possible where the API's name is filtered. A line that uses
// them is skipped when they could not be fetched.
const defaultAetherProfiles = `# Aether profiles, one per line:  label | flags
# Two at a time; fresh measurements for this network/core take priority.
# ktest adds the loopback bind address, the identity files and the prompts' answers.
WARP, MASQUE over HTTP/2 with ECH | --masque --h2 --fragment --ech {ECH} --enroll-address {ECHIP}
WARP, MASQUE over HTTP/3 (QUIC) with ECH | --masque --h3 --ech {ECH} --enroll-address {ECHIP}
WARP, WireGuard | --wg --noize balanced --ech {ECH} --enroll-address {ECHIP}
WARP, MASQUE over HTTP/2, fragmented | --masque --h2 --api-fragment
WARP, MASQUE over HTTP/3 | --masque --h3
WARP, WireGuard without ECH enrollment | --wg --noize balanced
WARP, Gool WireGuard over MASQUE H2 | --gool --h2
WARP, Gool WireGuard over MASQUE H3 | --gool --h3
WARP, MASQUE-in-MASQUE H2 | --mim --h2
WARP, MASQUE-in-MASQUE H3 | --mim --h3
WARP, classic WireGuard-in-WireGuard | --gool-classic
WARP, WireGuard, aggressive obfuscation | --wg --noize aggressive --ech {ECH} --enroll-address {ECHIP}
WARP, MASQUE over HTTP/2 with ECH, IPv6 | --masque --h2 --no-fragment -6 --ech {ECH} --enroll-address {ECHIP}
Psiphon | --psiphon-only
Psiphon through CDN fronting | --psiphon-only --psiphon-mode cdn
WARP, MASQUE over HTTP/2 with ECH, thorough scan | --masque --h2 --fragment --scan thorough --startup-secs 100 --ech {ECH} --enroll-address {ECHIP}
`

// aetherProfile is one way of running Aether.
type aetherProfile struct {
	Label string
	Args  []string
}

func (p aetherProfile) has(flag string) bool {
	for _, a := range p.Args {
		if a == flag || strings.HasPrefix(a, flag+"=") {
			return true
		}
	}
	return false
}

func (p aetherProfile) psiphon() bool { return p.has("--psiphon-only") }

// parseAetherProfiles reads "label | flags" lines, substituting the ECH
// placeholders and dropping lines that need what is not available.
func parseAetherProfiles(text, ech, ip string) ([]aetherProfile, error) {
	var out []aetherProfile
	seen := map[string]bool{}
	for n, line := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		label, flags, ok := strings.Cut(line, "|")
		label, flags = strings.TrimSpace(label), strings.TrimSpace(flags)
		if !ok || label == "" || flags == "" {
			return nil, fmt.Errorf("line %d: want \"label | flags\"", n+1)
		}
		args := strings.Fields(flags)
		for _, arg := range args {
			name, _, _ := strings.Cut(arg, "=")
			switch name {
			case "--bind", "--config", "--masque-config", "--wg-config", "--http-proxy", "--tor-bind", "--psiphon-bind", "--register":
				return nil, fmt.Errorf("line %d: %s is managed by ktest", n+1, name)
			}
		}
		if strings.Contains(flags, "{ECH") && (ech == "" || ip == "") {
			continue
		}
		flags = strings.NewReplacer("{ECHIP}", ip, "{ECH}", ech).Replace(flags)
		if seen[label] {
			return nil, fmt.Errorf("line %d: duplicate label %q", n+1, label)
		}
		seen[label] = true
		out = append(out, aetherProfile{Label: label, Args: strings.Fields(flags)})
		if len(out) > 64 {
			return nil, fmt.Errorf("at most 64 Aether profiles are supported")
		}
	}
	return out, nil
}

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
	return profilesForMode(profiles, mode), nil
}

// aetherRunArgs is the full command line of a profile on a local port. Every
// prompt Aether would ask has a flag here, so it never waits for input; flags
// the profile sets itself are not repeated.
func aetherRunArgs(i int, p aetherProfile, port int) []string {
	args := append([]string(nil), p.Args...)
	has := func(flags ...string) bool {
		for _, f := range flags {
			if p.has(f) {
				return true
			}
		}
		return false
	}
	if !p.psiphon() {
		if !has("-4", "-6", "--dual", "--ip") {
			args = append(args, "-4")
		}
		if !has("--scan", "--turbo", "--balanced", "--thorough", "--verified", "--ironclad") {
			args = append(args, "--turbo")
		}
		if !has("--startup-secs") {
			args = append(args, "--startup-secs", "45")
		}
		if !has("--quick-reconnect", "--no-quick-reconnect") {
			// Aether 2.3.0 can repeatedly select a failed cached gateway (upstream #147).
			// Explicit profile quick-reconnect settings still take precedence.
			args = append(args, "--no-quick-reconnect")
		}
	}
	return append(args,
		"--log-level", "warn",
		"--bind", fmt.Sprintf("127.0.0.1:%d", port),
		"--config", filepath.Join(warpDir(), "run-"+p.id()+".toml"),
		"--masque-config", identityFile(),
		"--wg-config", wireguardIdentityFile(),
	)
}

// attemptTimeout is how long a profile may take to open its proxy port.
func attemptTimeout(p aetherProfile) time.Duration {
	secs := 45
	for i, a := range p.Args {
		if a == "--startup-secs" && i+1 < len(p.Args) {
			fmt.Sscanf(p.Args[i+1], "%d", &secs)
		}
	}
	return time.Duration(secs+20) * time.Second
}

// A first-use nested method must bootstrap its inner identity over an outer
// tunnel before the final carrier can even start. That work cannot fit inside
// the standard 45-second probe. Existing valid identities take the fast path.
func profileAttemptBudget(p aetherProfile) time.Duration {
	// Aether's own startup deadline precedes independent SOCKS/exit checks.
	budget := attemptTimeout(p) + 15*time.Second
	if budget < 45*time.Second {
		budget = 45 * time.Second
	}
	var protocol, path string
	switch p.method() {
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

// Automatic discovery keeps a short first sweep. A forced/isolated slow
// profile must not be cancelled before its own configured startup deadline.
func (m *warpManager) searchBudget(indices []int) time.Duration {
	budget := 40 * time.Second
	forced := m.o.aetherMethod != "" && m.o.aetherMethod != "auto"
	if !forced && len(indices) > 2 {
		return budget
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
	if budget > 250*time.Second {
		budget = 250 * time.Second
	}
	return budget
}

// aetherPorts: one fixed port per profile index, so a profile that is found
// again after a drop is the same upstream.
func aetherPort(i int) int { return aetherBasePort + i }

type warpManager struct {
	o             connectOptions
	proxy         *smartproxy.Proxy
	dns           *dnscheck.Result
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
}

func (m *warpManager) status() string {
	total, verified := m.proxy.ExitCounts()
	phase := "retry pending"
	if m.searching.Load() {
		phase = "search continuing"
	} else if total > 0 {
		phase = "active"
	}
	status := fmt.Sprintf("%d %s available · %d AI-verified · %s", total, plural(total, "exit", "exits"), verified, phase)
	m.measureMu.Lock()
	defer m.measureMu.Unlock()
	if m.selected != nil {
		r := m.selected
		status += fmt.Sprintf(" · best measured %s · probe %s (%s) at %s", r.Method, r.ExitIP, r.Country, r.Checked.UTC().Format("15:04:05Z"))
	}
	return status
}

// startWarp runs the search for a working exit in the background and returns
// the note for the result box and the function that stops everything.
func startWarp(ctx context.Context, o connectOptions, proxy *smartproxy.Proxy, dns *dnscheck.Result, t *term, monitors ...*windscribeMonitor) (func() string, func()) {
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
	m, err := newWarpManager(ctx, o, proxy, dns, t, false)
	if err != nil {
		return fixed("off - " + err.Error())
	}
	if len(monitors) > 0 {
		m.monitor = monitors[0]
	}
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

// waitWhileConnected preserves an active foreign transport if Windscribe
// needs it as its own OpenVPN TCP upstream; it only pauses NEW discovery.
func (m *warpManager) waitWhileConnected(ctx context.Context) bool {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for m.monitor != nil && m.monitor.Connected() {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
	return ctx.Err() == nil
}

// waitRetry allows immediate recovery when Windscribe changes from connected
// to disconnected. Untried transports get a prompt turn; only a completed failed
// sweep backs off, so unavailable WARP cannot starve independent carriers.
func (m *warpManager) waitRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	sawConnected := m.monitor != nil && m.monitor.Connected()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		case <-tick.C:
			if m.monitor == nil {
				continue
			}
			if m.monitor.Connected() {
				sawConnected = true
			}
			if sawConnected && m.monitor.State() == windscribeDisconnected {
				return true
			}
		}
	}
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
	}
	retire := func(w *warpFound) {
		id := w.p.id()
		if current, ok := active[id]; !ok || current != w {
			return
		}
		w.rc.stop()
		if w.unregistered != nil {
			<-w.unregistered
		}
		delete(active, id)
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
		if len(active) < maxExits {
			m.searching.Store(true)
			found := m.search(ctx, active)
			m.searching.Store(false)
			for _, w := range found {
				active[w.p.id()] = w
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
		if len(active) >= maxExits {
			delay = 0
		} else if len(active) == 0 {
			m.t.Line(toneWarn, "No permitted exit verified; retrying discovery in %s (%d compatible profiles). Saved identities are kept.", delay, len(m.profs))
		} else {
			m.t.Note("%d/%d exits active; checking alternatives in %s", len(active), maxExits, delay)
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
		byID[p.id()] = i
	}
	var indices []int
	for _, p := range recoveryProfilesFirst(m.profs, history, m.o.mode) {
		if _, inUse := active[p.id()]; inUse || m.attempted[p.id()] {
			continue
		}
		indices = append(indices, byID[p.id()])
	}
	return indices
}

// Compare before exposing the initial choice. A cached winner gets one worker;
// first-use discovery has a shared deadline rather than delaying the UI for minutes.
func (m *warpManager) search(ctx context.Context, active map[string]*warpFound) []*warpFound {
	limit := maxExits - len(active)
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
	if len(active) == 0 && len(indices) > 0 {
		first := m.profs[indices[0]]
		if r, ok := history.Results[first.id()]; ok && (r.State == "verified" || m.o.mode == ModeWindscribeAether) && measurementScore(r, m.o.mode) < 1e12 && time.Since(r.Checked) < networkCacheTTL {
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
		err := m.proxy.Add(smartproxy.Upstream{Name: "Exit: " + r.p.Label, Addr: fmt.Sprintf("127.0.0.1:%d", r.port), Rank: 5 + i, Exit: true, AIEligible: r.result.State == "verified", Late: m.o.mode != ModeFast})
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
	if !p.psiphon() {
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
	logs := &tailBuffer{max: 8192}
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
	l := aetherLauncher(aetherBinary(m.o.base), aetherRunArgs(i, p, port), logs)
	go func() {
		defer close(rc.done)
		if logFile != nil {
			defer logFile.Close()
		}
		rc.err = l(cctx, m.dns)
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
	ready := waitForPort(ctx, rc.done, port, time.Until(deadline))
	if ready && exitCarries(ctx, rc.done, port, time.Until(deadline)) {
		return true, rc, ""
	}
	reason := "SOCKS listener did not open"
	switch {
	case ctx.Err() != nil:
		reason = "attempt cancelled or timed out"
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
func readyIdentity(p aetherProfile) bool {
	if p.psiphon() || p.has("--tor-only") {
		return true
	}
	protocol, path := "masque", identityFile()
	if p.method() == "wireguard" || p.method() == "wiw" {
		protocol, path = "wg", wireguardIdentityFile()
	}
	if checkWarpIdentity(path, protocol) != nil {
		return false
	}
	switch p.method() {
	case "wiw":
		return checkWarpIdentity(filepath.Join(warpDir(), "wg-secondary.toml"), "wg") == nil
	case "mim-h2", "mim-h3":
		return checkWarpIdentity(filepath.Join(warpDir(), "masque-secondary.toml"), "masque") == nil
	case "gool-h2", "gool-h3":
		return checkWarpIdentity(filepath.Join(warpDir(), "masque-gool.toml"), "wg") == nil
	}
	return true
}

func (m *warpManager) prepareIdentity(ctx context.Context, p aetherProfile) error {
	if p.psiphon() || p.has("--tor-only") {
		return nil // standalone carriers have no WARP enrollment requirement
	}
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
	if p.method() == "wireguard" || p.method() == "wiw" {
		protocol, path = "wg", wireguardIdentityFile()
	}
	if err := m.prepareIdentityFile(ctx, protocol, path, nil); err != nil {
		return err
	}
	switch {
	case p.method() == "wiw":
		return m.prepareIdentityFile(ctx, "wg", filepath.Join(warpDir(), "wg-secondary.toml"), nil)
	case strings.HasPrefix(p.method(), "mim-"):
		return m.prepareIdentityFile(ctx, "masque", filepath.Join(warpDir(), "masque-secondary.toml"), nil)
	case strings.HasPrefix(p.method(), "gool-"):
		inner := filepath.Join(warpDir(), "masque-gool.toml")
		if err := checkWarpIdentity(inner, "wg"); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		if m.enrollTried[inner] {
			return fmt.Errorf("Gool inner enrollment already attempted this connection; retry diagnosis or reconnect")
		}
		var args []string
		for i := 0; i < len(p.Args); i++ {
			arg := p.Args[i]
			if arg == "--protocol" && i+1 < len(p.Args) {
				args = append(args, arg, "masque")
				i++
				continue
			}
			if arg == "--gool" || arg == "--wiw" {
				args = append(args, "--masque")
				continue
			}
			if arg == "--gool-peer" {
				i++
				continue
			}
			args = append(args, arg)
		}
		outer := aetherProfile{Label: "Gool registration carrier " + p.method(), Args: args}
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
		if canUseEnrollmentProxy(m.o.mode, m.proxy) {
			proxyAddr = m.o.listen
		}
		m.enrollRoutes = enrollmentRoutes(ctx, m.o.base, proxyAddr, m.ech, m.echIP)
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
