// Package smartproxy is a local SOCKS5 front end that races several upstream
// paths (local proxy cores, each with a different anti-DPI method) for the
// first TLS flight of every connection and keeps the one that really answers.
//
// Why: censorship differs per site and per network, and a method that works
// today may fail tomorrow. Instead of the user picking one global method, each
// new TLS connection is offered to the paths in a learned order, staggered so
// the common case costs one connection. The decisive property is that nothing
// has reached the application before an upstream produced a TLS record: a
// failed attempt can be replayed on another path transparently.
//
// It does not weaken TLS (end-to-end handshake, the application verifies the
// certificate), does not install certificates and changes no system setting.
package smartproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Upstream is a SOCKS5 proxy without authentication. An empty Addr is the
// ordinary system route (local DNS, no proxy).
type Upstream struct {
	Name string
	Addr string
	// LocalDNS marks upstreams that resolve host names with the system
	// resolver (ByeDPI, the direct route). On a network that poisons DNS those
	// would connect to a bogus address, so the proxy resolves the name itself
	// through Config.Resolve and hands them an IP. Name-resolving upstreams
	// (Xray) keep receiving the name.
	LocalDNS bool
	// Send, when set, writes the first flight instead of a plain Write. It is
	// how built-in desync families cut the ClientHello.
	Send func(c net.Conn, flight []byte) error
	// Network is "tcp" (default) or "tcp6". IPv6 paths matter because some
	// networks filter the IPv4 and IPv6 data planes differently.
	Network string
	// SoftResolve makes a failed or poisoned lookup non-fatal: the path then
	// receives the name and resolves it itself (Xray has its own DNS and fake-IP
	// routing), instead of being skipped like a path that can only use system DNS.
	SoftResolve bool
	// Rank is the static preference when two paths have the same track record:
	// lower first. Plain connections are the least intrusive, cut ones the most.
	Rank int
	// Match, when set, restricts the path to the hosts it accepts. It is how a
	// path that only works for some sites (domain fronting) stays out of the way
	// of all the others.
	Match func(host string) bool
	// Exit marks a path that leaves from another address (a WARP or VPN exit).
	// Cutting or fronting cannot help a destination that is blocked by address,
	// so for traffic that is not TLS these are the only paths besides the direct
	// one worth trying.
	Exit bool
	// AIEligible means the remote exit IP was independently checked as non-Iran.
	// An external SOCKS listener opening is not sufficient to set this flag.
	AIEligible bool
	// LocalBypass is reserved for local anti-DPI SOCKS cores that dial the
	// destination themselves via the user's network, never via a foreign exit.
	// It is NOT inferred from a loopback address, which can hide a VPN.
	LocalBypass bool
	// Late keeps the path out of the race until every other path has failed or
	// lateAfter has passed, unless it is the remembered first choice. An exit
	// that carries everything through a third party should be the last resort,
	// not a competitor of the paths that reach the site directly.
	Late bool
	// Takeover, when set, replaces the relay: the path speaks TLS to the
	// application itself (it terminates the connection and re-originates it
	// toward the site). Prepare must do everything that can fail without the
	// application noticing, such as reaching the site, so that a failure here
	// leaves the other paths free to answer the unchanged ClientHello.
	Takeover func(ctx context.Context, host, port string, flight []byte) (Session, error)
}

// Session is a prepared takeover: the upstream side is ready, the application
// has not been answered yet.
type Session interface {
	// Serve answers the application, whose first flight (the ClientHello that
	// was already read) is flight, and relays until either side ends. It
	// returns an error when the application refused the connection, for
	// example because it does not trust the certificate that was presented.
	Serve(client net.Conn, flight []byte) error
	// Close releases the upstream side of a session that lost the race.
	Close()
}

type Config struct {
	Upstreams []Upstream
	// ExitOnly forces matched names to use only verified foreign exits.
	// If none is present, fail closed instead of silently revealing the ISP IP.
	ExitOnly func(string) bool
	// VerifyExit rechecks a previously eligible exit using a neutral destination.
	// Protected connections wait for a fresh successful check before dialing.
	VerifyExit    func(context.Context, Upstream) error
	VerifyCarrier func(context.Context, Upstream) error
	ExitVerifyTTL time.Duration
	// PreferVerifiedExit is useful for bootstrapping TCP VPN protocols: try an
	// already checked foreign proxy before a misleading raw TCP/IP connection.
	PreferVerifiedExit bool
	// RejectExits is defense-in-depth for Windscribe's local-only mode.
	// Both initial and dynamically added foreign routes are refused.
	RejectExits bool
	// LocalOnly forbids any path other than explicitly marked local anti-DPI
	// SOCKS cores or built-in ClientHello modifiers on direct connections.
	LocalOnly bool
	// Stagger bounds the preferred path's head start before the small fallback wave.
	Stagger time.Duration
	// ConnectTimeout bounds dial plus SOCKS handshake; FirstByteTimeout bounds
	// the wait for the server's first TLS record after the flight was sent.
	ConnectTimeout   time.Duration
	FirstByteTimeout time.Duration
	// MemoryTTL bounds exact host:port history and initial sibling hints.
	MemoryTTL time.Duration
	// Resolve (A records) and Resolve6 (AAAA records) are used for LocalDNS
	// upstreams; nil leaves them on system DNS.
	Resolve  Resolver
	Resolve6 Resolver
	// ExchangeDNS forwards complete DNS messages over an encrypted transport.
	// UDP port 53 is intercepted here and never sent to the system resolver.
	ExchangeDNS func(context.Context, []byte) ([]byte, error)
	// Logf receives one line per decision; nil is silent.
	Logf func(format string, args ...any)
	// OnEvent reports raced outcomes and unverified local TCP establishment;
	// it must not block.
	OnEvent func(Event)
}

// Event reports a connection outcome, or unverified TCP establishment.
type Event struct {
	Probe       bool // internal calibration listener; never counts as user activity
	Host        string
	Site        string // grouped domain for aggregate reporting; never the exact history key
	Port        string
	TLSResponse bool   // a complete, structurally valid ServerHello was received
	Prepared    bool   // takeover prepared; application TLS acceptance is still pending
	EarlyClose  bool   // route ended before post-hello response data; not a second request
	Path        string // winning path; empty when none answered
	Egress      string // route class; never a fabricated destination-observed IP
	Took        time.Duration
	OK          bool
	Err         string // last failure reason when no path answered
	// TCPOnly means only the upstream TCP/SOCKS handshake succeeded. It must
	// not be counted as an answered application connection or a working VPN.
	TCPOnly bool
	// Rejected marks a connection that a takeover path prepared but the
	// application then refused (it does not trust the certificate presented).
	Rejected bool
}

func (c *Config) defaults() {
	if c.ExitVerifyTTL <= 0 {
		c.ExitVerifyTTL = 5 * time.Minute
	}
	if c.Stagger <= 0 {
		c.Stagger = 300 * time.Millisecond
	}
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = 5 * time.Second
	}
	if c.FirstByteTimeout <= 0 {
		c.FirstByteTimeout = 5 * time.Second
	}
	if c.MemoryTTL <= 0 {
		c.MemoryTTL = 30 * time.Minute
	}
}

// Stat summarizes one upstream since start.
type Stat struct {
	Name     string
	Wins     int
	Failures int
	AvgMS    int64
}

type upstreamState struct {
	Upstream
	carrierMu     sync.Mutex
	carrierUntil  time.Time
	wins, fails   int
	ewmaMS        float64
	verifiedUntil atomic.Int64
	verifyMu      sync.Mutex
	verifyErr     error
	retryAfter    time.Time
}

type memo struct {
	name string
	at   time.Time
}

type Proxy struct {
	cfg             Config
	mu              sync.Mutex
	ups             []*upstreamState
	mem             map[string]*destinationMemory
	hints           map[string]memo
	historyUpdates  uint64
	exitGeneration  uint64          // changes when the DNS-capable exit inventory changes
	aiPinned        string          // first working AI exit stays selected until this session ends
	bootstrapPinned string          // legacy verified foreign-exit dialer; never used for local bypass
	localAttempts   map[string]memo // last local method attempted per exact host:port
}

func allowedLocalOnly(u Upstream) bool {
	if u.Exit || u.Takeover != nil {
		return false
	}
	if u.LocalBypass && u.Addr != "" {
		host, _, err := net.SplitHostPort(u.Addr)
		if err != nil {
			return false
		}
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	}
	// An ordinary direct connection has no Send function; it is forbidden.
	// A built-in TLS ClientHello modification uses the ISP's own network.
	return u.Addr == "" && u.Send != nil
}

func New(cfg Config) (*Proxy, error) {
	if len(cfg.Upstreams) == 0 && cfg.ExitOnly == nil {
		return nil, errors.New("at least one upstream is required")
	}
	cfg.defaults()
	p := &Proxy{cfg: cfg, mem: map[string]*destinationMemory{}, hints: map[string]memo{}}
	seen := map[string]bool{}
	for _, u := range cfg.Upstreams {
		if cfg.RejectExits && u.Exit {
			return nil, fmt.Errorf("foreign exit %q prohibited by local-only mode", u.Name)
		}
		if cfg.LocalOnly && !allowedLocalOnly(u) {
			return nil, fmt.Errorf("nonlocal/plain route %q prohibited by Windscribe local-only mode", u.Name)
		}
		if u.Name == "" || seen[u.Name] {
			return nil, fmt.Errorf("upstream names must be unique and non-empty (%q)", u.Name)
		}
		seen[u.Name] = true
		state := &upstreamState{Upstream: u}
		if u.AIEligible {
			state.verifiedUntil.Store(time.Now().Add(cfg.ExitVerifyTTL).UnixNano())
		}
		p.ups = append(p.ups, state)
		if u.Exit {
			p.exitGeneration++
		}
	}
	return p, nil
}

func (p *Proxy) logf(format string, args ...any) {
	if p.cfg.Logf != nil {
		p.cfg.Logf(format, args...)
	}
}

// Stats returns per-upstream results, best first.
func (p *Proxy) Stats() []Stat {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Stat, 0, len(p.ups))
	for _, u := range p.ups {
		out = append(out, Stat{Name: u.Name, Wins: u.wins, Failures: u.fails, AvgMS: int64(u.ewmaMS)})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Wins > out[j].Wins })
	return out
}

// Winners returns the preferred upstream per exact host:port (for display only).
func (p *Proxy) Winners() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]string, len(p.mem))
	for h, m := range p.mem {
		if time.Since(m.updated) < p.cfg.MemoryTTL && m.winner != "" {
			out[h] = m.winner
		}
	}
	return out
}

// HasVerifiedExit reports whether a foreign TCP exit has been verified.
// Opening an arbitrary local SOCKS port or reaching a web front is not enough.
func (p *Proxy) HasVerifiedExit() bool {
	_, verified := p.ExitCounts()
	return verified > 0
}

// ExitCounts reports registered exits and those independently geo-verified.
func (p *Proxy) ExitCounts() (total, verified int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, u := range p.ups {
		if u.Exit {
			total++
			if u.AIEligible && (p.cfg.VerifyExit == nil || time.Now().UnixNano() < u.verifiedUntil.Load()) {
				verified++
			}
		}
	}
	return
}

// Remove unregisters a dead external exit without breaking active sessions
// which already own a net.Conn. Future connections can no longer select it.
func (p *Proxy) Remove(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, u := range p.ups {
		if u.Name == name {
			if u.Exit {
				p.exitGeneration++
			}
			p.ups = append(p.ups[:i], p.ups[i+1:]...)
			break
		}
	}
	for _, m := range p.mem {
		delete(m.routes, name)
		if m.winner == name {
			m.winner = ""
		}
		if m.challenger == name {
			m.challenger, m.challengeWins = "", 0
		}
	}
	for host, hint := range p.hints {
		if hint.name == name {
			delete(p.hints, host)
		}
	}
	// The AI policy must not silently jump between identities; it remains
	// pinned and fails closed if a previously chosen exit disappeared.
	// Windscribe's outer carrier may recover after a dead core; its own
	// authenticated VPN retains ownership of application identity.
	if p.bootstrapPinned == name {
		p.bootstrapPinned = ""
	}
}

// ExitCarriers is a current snapshot for neutral, certificate-verified DNS
// requests. It does not grant AI eligibility or change any pinned identity.
func (p *Proxy) ExitCarriers() ([]string, uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var addrs []string
	for _, u := range p.ups {
		if u.Exit && u.Addr != "" {
			addrs = append(addrs, u.Addr)
		}
	}
	return addrs, p.exitGeneration
}

// HasLocalBypass reports whether an explicitly trusted local anti-DPI SOCKS
// listener is registered. It does not prove that Windscribe's handshake works.
func (p *Proxy) HasLocalBypass() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, u := range p.ups {
		if u.LocalBypass && !u.Exit && u.Takeover == nil && u.Addr != "" {
			return true
		}
	}
	return false
}

// DialLocalBypass is the only authorized Windscribe bootstrap dialer. It
// rejects direct/plain and all exits, Tor, Aether, Psiphon, and takeover
// fronting. The core must be a ktest-managed local TCP DPI bypass. A successful
// SOCKS reply only confirms upstream TCP connectivity, not a VPN handshake.
func (p *Proxy) DialLocalBypass(ctx context.Context, host, port string) (net.Conn, error) {
	return p.dialLocalBypass(ctx, host, port, true)
}

// DialWindscribeCarrier uses the same local-only policy and retry rotation,
// but leaves feed reporting to the outer WStunnel/Stealth race.
func (p *Proxy) DialWindscribeCarrier(ctx context.Context, host, port string) (net.Conn, error) {
	return p.dialLocalBypass(ctx, host, port, false)
}

func (p *Proxy) dialLocalBypass(ctx context.Context, host, port string, report bool) (net.Conn, error) {
	if p.cfg.ExitOnly != nil && p.cfg.ExitOnly(host) {
		return nil, errors.New("protected AI domains cannot use the local Windscribe bootstrap bridge")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	var candidates []*upstreamState
	for _, u := range p.ups {
		if !u.LocalBypass || !allowedLocalOnly(u.Upstream) || u.Addr == "" || (u.Match != nil && !u.Match(host)) {
			continue
		}
		candidates = append(candidates, u)
	}
	if len(candidates) == 0 {
		p.mu.Unlock()
		return nil, errors.New("Windscribe: no local IP-preserving anti-DPI TCP path; no foreign exit will be used")
	}
	// Use stable candidate order, not scores from incidental TLS/API traffic.
	// Each new CONNECT is an independent attempt: a SOCKS acknowledgement
	// cannot tell us whether the opaque VPN protocol will subsequently work.
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].Rank < candidates[j].Rank })
	key := net.JoinHostPort(strings.ToLower(strings.TrimSuffix(host, ".")), port)
	if last, ok := p.localAttempts[key]; ok && time.Since(last.at) < p.cfg.MemoryTTL {
		for i, u := range candidates {
			if u.Name == last.name {
				candidates = append(candidates[i+1:], candidates[:i+1]...)
				break
			}
		}
	}
	if p.localAttempts == nil {
		p.localAttempts = make(map[string]memo)
	}
	// Reserve before dialing so simultaneous CONNECTs do not all pick the
	// first method. A failed TCP dial advances to the remaining candidates.
	p.localAttempts[key] = memo{name: candidates[0].Name, at: time.Now()}
	p.mu.Unlock()
	var lastErr error
	for i, u := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if i > 0 {
			p.mu.Lock()
			p.localAttempts[key] = memo{name: u.Name, at: time.Now()}
			p.mu.Unlock()
		}
		began := time.Now()
		conn, err := p.dial(ctx, u, host, port)
		if err != nil {
			p.record(u, host, port, false, time.Since(began))
			lastErr = err
			continue
		}
		p.logf("Windscribe CONNECT %s:%s accepted via local anti-DPI %s (destination/VPN negotiation not yet verified)", host, port, u.Name)
		if report {
			p.emit(ctx, Event{Host: host, Port: port, Site: siteKey(host), Path: u.Name, Took: time.Since(began), TCPOnly: true})
		}
		return conn, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("all local Windscribe DPI bypass paths failed TCP CONNECT: %w", lastErr)
	}
	return nil, errors.New("all local Windscribe DPI bypass paths failed TCP CONNECT")
}

// DialWindscribeLocal is retained as a compatibility alias for existing
// callers and tests. All policy checks and per-destination rotation live in one
// strict, loopback-only local anti-DPI implementation.
func (p *Proxy) DialWindscribeLocal(ctx context.Context, host, port string) (net.Conn, error) {
	return p.DialLocalBypass(ctx, host, port)
}

// DialVerifiedExit is a separate verified foreign TCP transport. Windscribe's
// local-only HTTP proxy never calls it. It waits until the foreign SOCKS
// upstream acknowledges a connection to the destination. No direct,
// ByeDPI, Xray-fragment or fronting fallback is allowed for this transport.
// After the first real TCP connection, the chosen exit stays pinned for this
// session to prevent accidental mid-session route/identity switching.
func (p *Proxy) DialVerifiedExit(ctx context.Context, host, port string) (net.Conn, error) {
	return p.dialManagedExit(ctx, host, port, true)
}

// Windscribe's authenticated VPN can use a proven WARP carrier even when that
// carrier exits in Iran. This never grants access to protected AI destinations.
func (p *Proxy) DialExitCarrier(ctx context.Context, host, port string) (net.Conn, error) {
	if p.cfg.ExitOnly != nil && p.cfg.ExitOnly(host) {
		return p.DialVerifiedExit(ctx, host, port)
	}
	return p.dialManagedExit(ctx, host, port, false)
}

func (p *Proxy) dialManagedExit(ctx context.Context, host, port string, foreign bool) (net.Conn, error) {
	p.mu.Lock()
	pinned := p.bootstrapPinned
	p.mu.Unlock()
	candidates := p.order(host, port)
	var lastErr error
	any := false
	for _, u := range candidates {
		if !u.Exit || (foreign && !u.AIEligible) || (pinned != "" && u.Name != pinned) {
			continue
		}
		any = true
		var verification error
		if foreign {
			verification = p.verifyExit(ctx, u)
		} else {
			verification = p.verifyCarrier(ctx, u)
		}
		if err := verification; err != nil {
			lastErr = err
			continue
		}
		began := time.Now()
		conn, err := p.dial(ctx, u, host, port)
		if err != nil {
			p.record(u, host, port, false, time.Since(began))
			lastErr = err
			continue
		}
		p.mu.Lock()
		if p.bootstrapPinned == "" {
			p.bootstrapPinned = u.Name
		}
		accepted := p.bootstrapPinned == u.Name
		p.mu.Unlock()
		if !accepted {
			_ = conn.Close()
			continue
		}
		if !p.record(u, host, port, true, time.Since(began)) {
			_ = conn.Close()
			lastErr = errors.New("foreign exit changed while connecting")
			continue
		}
		p.logf("Foreign transport CONNECT %s:%s carried through verified exit %s", host, port, u.Name)
		p.emit(ctx, Event{Host: host, Port: port, Site: siteKey(host), Path: u.Name, Took: time.Since(began), TCPOnly: true})
		return conn, nil
	}
	if !any {
		if foreign {
			return nil, errors.New("foreign transport blocked: no verified foreign TCP exit")
		}
		return nil, errors.New("foreign transport blocked: no eligible verified exit carrier")
	}
	if lastErr != nil {
		return nil, fmt.Errorf("verified exit is unreachable: %w", lastErr)
	}
	return nil, errors.New("Windscribe bootstrap exit changed; reconnect ktest explicitly to select another")
}

// Serve accepts SOCKS5 clients until ctx ends.
type probeContextKey struct{}

// ServeProbes shares route learning but permanently tags this listener's
// events, including results arriving after a calibration client times out.
func (p *Proxy) ServeProbes(ctx context.Context, l net.Listener) error {
	return p.Serve(context.WithValue(ctx, probeContextKey{}, true), l)
}

func (p *Proxy) Serve(ctx context.Context, l net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go p.handle(ctx, c)
	}
}

func (p *Proxy) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	rawClient := client
	stopClient := context.AfterFunc(ctx, func() { _ = rawClient.Close() })
	defer stopClient()
	command, host, port, err := socksCommand(client)
	if err != nil {
		return
	}
	if command == 3 {
		p.serveUDP(ctx, client, host, port)
		return
	}
	// Success is announced before any upstream is known: a TLS client only
	// sends its ClientHello after this reply.
	if _, err := client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	if port == "53" && p.cfg.ExchangeDNS != nil {
		p.serveDNSStream(ctx, client)
		return
	}
	identityRequired := p.cfg.ExitOnly != nil && !p.cfg.ExitOnly(host)
	firstByteWait := 400 * time.Millisecond
	if identityRequired {
		firstByteWait = 2 * time.Second
	}
	flight, extra, err := readFirstFlight(client, firstByteWait)
	if err != nil {
		if ctx.Err() == nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			p.emit(ctx, Event{Host: host, Port: port, Site: siteKey(host), Err: err.Error()})
		}
		return
	}
	if len(flight) == 0 && identityRequired {
		p.emit(ctx, Event{Host: host, Port: port, Site: siteKey(host), Err: "No client identity received; server-first traffic requires a verified foreign-only mode"})
		return
	}
	if len(extra) > 0 {
		client = &pendingConn{Conn: client, pending: extra}
	}
	var win winner
	if isTLSFlight(flight) {
		host = p.nameFor(host, flight)
		win, err = p.race(ctx, host, port, flight)
	} else {
		began := time.Now()
		win, err = p.plain(ctx, host, port, flight)
		if ctx.Err() == nil {
			e := Event{Host: host, Port: port, Site: siteKey(host), Path: win.path, Took: time.Since(began)}
			if err != nil {
				e.Err = err.Error()
			} else {
				e.OK = len(win.first) > 0
				e.TCPOnly = !e.OK
			}
			p.emit(ctx, e)
		}
	}
	if err != nil {
		p.logf("%s:%s no path answered: %v", host, port, err)
		return
	}
	stopWinner := context.AfterFunc(ctx, win.release)
	defer stopWinner()
	if win.sess != nil {
		if err := win.sess.Serve(client, flight); err != nil {
			p.rejectTakeover(host, port, win.path)
			p.logf("%s:%s %s: %v", host, port, win.path, err)
			p.emit(ctx, Event{Host: host, Port: port, Site: siteKey(host), Path: win.path, Err: err.Error(), Rejected: true})
		}
		return
	}
	defer win.conn.Close()
	if len(win.first) > 0 {
		if _, err := client.Write(win.first); err != nil {
			return
		}
	}
	result := pipe(client, win.conn)
	if win.tls && ctx.Err() == nil {
		p.observeRelay(ctx, host, port, win.path, result)
	}
}

// nameFor returns the name a connection is about: the SOCKS host, except when
// the application resolved the name itself and got a poisoned (private) answer,
// in which case the SNI of its ClientHello is the only truthful name left. This
// is what lets an application that ignores "proxy DNS" still work.
func (p *Proxy) nameFor(host string, flight []byte) string {
	if sni, _, ok := ParseClientHello(flight); ok && sni != "" && p.cfg.ExitOnly != nil && p.cfg.ExitOnly(sni) {
		return sni
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if sni, _, ok := ParseClientHello(flight); ok && sni != "" && net.ParseIP(sni) == nil {
		if Bogus(ip) {
			p.logf("%s is a block-page address; using the SNI %s instead", host, sni)
			return sni
		}
	}
	return host
}

type outcome struct {
	u    *upstreamState
	win  winner
	took time.Duration
	err  error
}

// winner is what a successful attempt hands to handle: either an upstream
// connection that already produced a TLS record, or a prepared takeover.
type winner struct {
	conn  net.Conn
	first []byte
	sess  Session
	tls   bool
	path  string
}

func (w winner) release() {
	if w.conn != nil {
		_ = w.conn.Close()
	}
	if w.sess != nil {
		w.sess.Close()
	}
}

// race first tries the preferred path, then up to three concurrent candidates.
// If these stay silent, all remaining normal routes join after a bounded
// 250ms hedge. Explicit Late routes retain their separate last-resort gate.
func (p *Proxy) race(parent context.Context, host, port string, flight []byte) (winner, error) {
	began := time.Now()
	if err := parent.Err(); err != nil {
		return winner{}, err
	}
	order := p.order(host, port)
	if len(order) == 0 {
		return winner{}, fmt.Errorf("%s: no permitted foreign exit; protected site blocked (fail-closed)", host)
	}
	// Late paths go to the back, behind a gate that opens when everything else
	// has failed or after lateAfter.
	remembered := p.rememberedName(host, port)
	var ordered, late []*upstreamState
	for _, u := range order {
		if u.Late && u.Name != remembered && !(p.cfg.PreferVerifiedExit && u.Exit && u.AIEligible) {
			late = append(late, u)
		} else {
			ordered = append(ordered, u)
		}
	}
	if len(ordered) == 0 { // nothing but last resorts exists: they are the race
		ordered, late = late, nil
	}
	limit := len(ordered)
	order = append(ordered, late...)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	results := make(chan outcome, len(order))
	next, pending := 0, 0
	launch := func(n int) {
		for ; n != 0 && next < limit; n-- {
			u := order[next]
			next++
			pending++
			go func() {
				began := time.Now()
				w, err := p.attempt(ctx, u, host, port, flight)
				results <- outcome{u, w, time.Since(began), err}
			}()
		}
	}
	wave := p.firstWave(order[0], host, port)
	launch(1)
	timer := time.NewTimer(wave)
	defer timer.Stop()
	hedge := time.NewTimer(wave + 250*time.Millisecond)
	defer hedge.Stop()
	expanded := false
	refill := func() {
		if expanded {
			launch(-1)
		} else {
			launch(max(3-pending, 0))
		}
	}
	lateGate := time.NewTimer(lateAfter)
	defer lateGate.Stop()
	var lastErr error
	for pending > 0 || next < len(order) {
		if pending == 0 && next >= limit && limit < len(order) {
			limit = len(order) // everything else failed: the last resort may go
			expanded = true
			launch(-1)
		}
		select {
		case <-parent.Done():
			go drain(results, pending)
			return winner{}, parent.Err()
		case <-lateGate.C:
			limit = len(order)
			expanded = true
			launch(-1)
		case <-timer.C:
			refill()
		case <-hedge.C:
			expanded = true
			launch(-1)
		case r := <-results:
			pending--
			if parent.Err() != nil {
				r.win.release()
				go drain(results, pending)
				return winner{}, parent.Err()
			}
			if r.err != nil {
				lastErr = fmt.Errorf("%s: %w", r.u.Name, r.err)
				p.record(r.u, host, port, false, r.took)
				p.logf("%s:%s %s failed: %v", host, port, r.u.Name, r.err)
				refill()
				continue
			}
			if !p.record(r.u, host, port, true, r.took) {
				r.win.release()
				lastErr = errors.New("another connection pinned a different foreign exit")
				refill()
				continue
			}
			p.logf("%s:%s won by %s in %dms", host, port, r.u.Name, r.took.Milliseconds())
			p.emit(parent, Event{Host: host, Port: port, Site: siteKey(host), Path: r.u.Name, Took: time.Since(began), OK: true, TLSResponse: r.win.tls, Prepared: r.win.sess != nil})
			cancel()
			go drain(results, pending)
			r.win.path = r.u.Name
			return r.win, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream")
	}
	p.emit(parent, Event{Host: host, Port: port, Site: siteKey(host), Err: lastErr.Error()})
	return winner{}, lastErr
}

// lateAfter is how long a Late path waits behind the others at most.
const lateAfter = 3 * time.Second

func (p *Proxy) emit(ctx context.Context, e Event) {
	e.Probe, _ = ctx.Value(probeContextKey{}).(bool)
	if p.cfg.OnEvent != nil {
		p.mu.Lock()
		for _, u := range p.ups {
			if u.Name == e.Path {
				switch {
				case u.Exit:
					e.Egress = "proxy exit"
				case u.Takeover != nil:
					e.Egress = "CDN route; IP unmeasured"
				case u.LocalBypass || u.Addr == "":
					e.Egress = "system route"
				default:
					e.Egress = "proxy route; IP unmeasured"
				}
				break
			}
		}
		p.mu.Unlock()
		p.cfg.OnEvent(e)
	}
}

// siteKey groups hosts for reporting and initial hints only. Exact routing
// history always uses host:port. This is an approximation of the registrable
// domain without a public-suffix list.
func siteKey(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	labels := strings.Split(host, ".")
	n := len(labels)
	if n <= 2 {
		return host
	}
	tld, sld := labels[n-1], labels[n-2]
	if len(tld) == 2 {
		switch sld {
		case "co", "com", "org", "net", "gov", "edu", "ac":
			return strings.Join(labels[n-3:], ".")
		}
	}
	return strings.Join(labels[n-2:], ".")
}

// drain closes connections of attempts that lost the race.
func drain(results <-chan outcome, pending int) {
	for ; pending > 0; pending-- {
		r := <-results
		r.win.release()
	}
}

// attempt requires a complete, structurally valid ServerHello before selection.
func (p *Proxy) attempt(ctx context.Context, u *upstreamState, host, port string, flight []byte) (winner, error) {
	if u.Takeover != nil {
		tctx, cancel := context.WithTimeout(ctx, p.cfg.ConnectTimeout+p.cfg.FirstByteTimeout)
		defer cancel()
		sess, err := u.Takeover(tctx, host, port, flight)
		if err != nil {
			return winner{}, err
		}
		if ctx.Err() != nil { // the race was decided elsewhere meanwhile
			sess.Close()
			return winner{}, context.Canceled
		}
		return winner{sess: sess}, nil
	}
	conn, err := p.dial(ctx, u, host, port)
	if err != nil {
		return winner{}, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	fail := func(err error) (winner, error) {
		stop()
		_ = conn.Close()
		return winner{}, err
	}
	_ = conn.SetDeadline(time.Now().Add(p.cfg.FirstByteTimeout))
	send := u.Send
	if send == nil {
		send = func(c net.Conn, f []byte) error { _, err := c.Write(f); return err }
	}
	if err := send(conn, flight); err != nil {
		return fail(err)
	}
	response, err := readServerHello(conn)
	if err != nil {
		return fail(err)
	}
	if !stop() { // ctx already ended, the race was decided elsewhere
		_ = conn.Close()
		return winner{}, context.Canceled
	}
	_ = conn.SetDeadline(time.Time{})
	return winner{conn: conn, first: response, tls: true}, nil
}

// plain handles non-TLS traffic: nothing cuts a protocol it cannot parse, so
// only the direct route and exit paths are tried, in learned order. The outcome
// is remembered per destination, so a destination that is blocked goes to the
// exit first the next time.
//
// A connection that opens is not proof that the route works: a filter may let
// the TCP handshake through and drop the protocol's first bytes (Telegram's
// MTProto is dropped this way). When the application speaks first to a
// destination named by address, so that no TLS is there to check, the first
// flight is therefore offered to the direct route and the exits and the first
// to answer is kept. Only the application's own first flight is repeated, to
// machines it was already sending it to.
func (p *Proxy) plain(ctx context.Context, host, port string, flight []byte) (winner, error) {
	all := p.order(host, port)
	var cands []*upstreamState
	for _, u := range all {
		if p.cfg.LocalOnly {
			// The in-process ClientHello cutters are direct TCP once passed a
			// non-TLS flight. They must never masquerade as an anti-DPI
			// method for raw OpenVPN traffic.
			if u.LocalBypass && !u.Exit && u.Addr != "" && u.Takeover == nil {
				cands = append(cands, u)
			}
			continue
		}
		if u.Takeover == nil && (u.Addr == "" || u.Exit) {
			cands = append(cands, u)
		}
	}
	// Raw OpenVPN/TCP traffic is not a TLS ClientHello. If an externally
	// verified path exists for Windscribe bootstrap, never race it against a
	// misleading direct TCP socket which can connect but drop later packets.
	if p.cfg.PreferVerifiedExit {
		var verified []*upstreamState
		for _, u := range cands {
			if u.Exit && u.AIEligible {
				verified = append(verified, u)
			}
		}
		if len(verified) > 0 {
			cands = verified
		}
	}
	if len(cands) == 0 && !p.cfg.LocalOnly { // no direct or exit path configured: use whatever relays
		for _, u := range all {
			if u.Takeover == nil {
				cands = append(cands, u)
			}
		}
	}
	if len(cands) > 1 && len(flight) > 0 && net.ParseIP(host) != nil && p.rememberedName(host, port) == "" {
		return p.racePlain(ctx, cands, host, port, flight)
	}
	var lastErr error
	for _, u := range cands {
		began := time.Now()
		conn, err := p.dial(ctx, u, host, port)
		if err == nil && len(flight) > 0 {
			if _, werr := conn.Write(flight); werr != nil {
				_ = conn.Close()
				conn, err = nil, werr
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return winner{}, ctx.Err()
			}
			p.record(u, host, port, false, time.Since(began))
			lastErr = fmt.Errorf("%s: %w", u.Name, err)
			continue
		}
		if !p.record(u, host, port, true, time.Since(began)) {
			_ = conn.Close()
			lastErr = errors.New("foreign exit changed while connecting")
			continue
		}
		return winner{conn: conn, path: u.Name}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream")
	}
	return winner{}, lastErr
}

// racePlain offers the first flight to every candidate, the best first and the
// others after a short delay or as soon as it fails, and keeps the first one
// that sends bytes back.
func (p *Proxy) racePlain(parent context.Context, cands []*upstreamState, host, port string, flight []byte) (winner, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	type res struct {
		u     *upstreamState
		conn  net.Conn
		first []byte
		took  time.Duration
		err   error
	}
	results := make(chan res, len(cands))
	next, pending := 0, 0
	launch := func(n int) {
		for ; n != 0 && next < len(cands); n-- {
			u := cands[next]
			next++
			pending++
			go func() {
				began := time.Now()
				conn, err := p.dial(ctx, u, host, port)
				if err != nil {
					results <- res{u: u, err: err, took: time.Since(began)}
					return
				}
				stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
				_ = conn.SetDeadline(time.Now().Add(p.cfg.FirstByteTimeout))
				if _, err := conn.Write(flight); err != nil {
					stop()
					_ = conn.Close()
					results <- res{u: u, err: err, took: time.Since(began)}
					return
				}
				buf := make([]byte, 4096)
				n, err := conn.Read(buf)
				if n == 0 {
					stop()
					_ = conn.Close()
					if err == nil {
						err = errors.New("no answer")
					}
					results <- res{u: u, err: fmt.Errorf("no answer: %w", err), took: time.Since(began)}
					return
				}
				if !stop() {
					_ = conn.Close()
					results <- res{u: u, err: context.Canceled}
					return
				}
				_ = conn.SetDeadline(time.Time{})
				results <- res{u: u, conn: conn, first: buf[:n], took: time.Since(began)}
			}()
		}
	}
	launch(1)
	timer := time.NewTimer(600 * time.Millisecond)
	defer timer.Stop()
	var lastErr error
	for pending > 0 || next < len(cands) {
		select {
		case <-parent.Done():
			go func(left int) {
				for ; left > 0; left-- {
					if r := <-results; r.conn != nil {
						_ = r.conn.Close()
					}
				}
			}(pending)
			return winner{}, parent.Err()
		case <-timer.C:
			launch(1)
			if next < len(cands) {
				timer.Reset(600 * time.Millisecond)
			}
		case r := <-results:
			pending--
			if r.err != nil {
				if parent.Err() == nil {
					p.record(r.u, host, port, false, r.took)
				}
				lastErr = fmt.Errorf("%s: %w", r.u.Name, r.err)
				launch(1) // the one in front failed: the next goes now
				continue
			}
			if !p.record(r.u, host, port, true, r.took) {
				_ = r.conn.Close()
				lastErr = errors.New("foreign exit changed while connecting")
				launch(1)
				continue
			}
			p.logf("%s:%s answered through %s in %dms", host, port, r.u.Name, r.took.Milliseconds())
			cancel()
			go func(left int) {
				for ; left > 0; left-- {
					if x := <-results; x.conn != nil {
						_ = x.conn.Close()
					}
				}
			}(pending)
			return winner{conn: r.conn, first: r.first, path: r.u.Name}, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream")
	}
	return winner{}, lastErr
}

// Add joins an upstream to the race while the proxy runs, for paths that take
// a while to come up (a tunnel that has to scan first).
func (p *Proxy) Add(u Upstream) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if u.Name == "" {
		return errors.New("upstream name is required")
	}
	if p.cfg.RejectExits && u.Exit {
		return errors.New("foreign exit is prohibited by local-only Windscribe mode")
	}
	if p.cfg.LocalOnly && !allowedLocalOnly(u) {
		return errors.New("nonlocal/plain route prohibited by Windscribe local-only mode")
	}
	for _, x := range p.ups {
		if x.Name == u.Name {
			return fmt.Errorf("upstream %q already exists", u.Name)
		}
	}
	state := &upstreamState{Upstream: u}
	if u.AIEligible {
		state.verifiedUntil.Store(time.Now().Add(p.cfg.ExitVerifyTTL).UnixNano())
	}
	p.ups = append(p.ups, state)
	if u.Exit {
		p.exitGeneration++
	}
	return nil
}

func (p *Proxy) dial(ctx context.Context, u *upstreamState, host, port string) (net.Conn, error) {
	if p.cfg.ExitOnly != nil && p.cfg.ExitOnly(host) {
		if !u.Exit || !u.AIEligible {
			return nil, errors.New("protected destination requires a verified foreign exit")
		}
		if err := p.verifyExit(ctx, u); err != nil {
			return nil, err
		}
	}
	dctx, cancel := context.WithTimeout(ctx, p.cfg.ConnectTimeout)
	defer cancel()
	d := net.Dialer{}
	network, resolver := "tcp", p.cfg.Resolve
	if u.Network == "tcp6" {
		network, resolver = "tcp6", p.cfg.Resolve6
	}
	if (u.LocalDNS || u.Addr == "") && resolver != nil && net.ParseIP(host) == nil {
		ip, err := p.resolve(dctx, resolver, host)
		switch {
		case err == nil:
			host = ip
		case u.SoftResolve && ctx.Err() == nil:
			p.logf("%s: no trusted address (%v); %s resolves it itself", host, err, u.Name)
		case errors.Is(err, ErrPoisoned):
			// Connecting to a block-page address would only look like a
			// network failure; say what it is and let other paths try.
			return nil, err
		case ctx.Err() != nil:
			return nil, ctx.Err()
		default:
			p.logf("%s: no trusted address (%v); using the name as given", host, err)
		}
	}
	if u.Addr == "" {
		return d.DialContext(dctx, network, net.JoinHostPort(host, port))
	}
	conn, err := d.DialContext(dctx, "tcp", u.Addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(p.cfg.ConnectTimeout))
	if err := socksConnect(conn, host, port); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func isTLSFlight(b []byte) bool {
	return len(b) >= 6 && b[0] == 0x16 && b[1] == 3 && b[5] == 0x01 // handshake, ClientHello
}

func socksCommand(c net.Conn) (command byte, host, port string, err error) {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	hdr := make([]byte, 2)
	if _, err = io.ReadFull(c, hdr); err != nil {
		return
	}
	if hdr[0] != 5 {
		return 0, "", "", errors.New("not SOCKS5")
	}
	methods := make([]byte, hdr[1])
	if _, err = io.ReadFull(c, methods); err != nil {
		return
	}
	if !bytes.Contains(methods, []byte{0}) {
		_, _ = c.Write([]byte{5, 0xff})
		return 0, "", "", errors.New("no acceptable auth method")
	}
	if _, err = c.Write([]byte{5, 0}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err = io.ReadFull(c, req); err != nil {
		return
	}
	if req[0] != 5 || req[2] != 0 || (req[1] != 1 && req[1] != 3) {
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return 0, "", "", errors.New("invalid SOCKS request or unsupported command")
	}
	command = req[1]
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, err = io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err = io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		if _, err = io.ReadFull(c, l); err != nil {
			return
		}
		b := make([]byte, l[0])
		if _, err = io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	default:
		_, _ = c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return 0, "", "", errors.New("unsupported address type")
	}
	pb := make([]byte, 2)
	if _, err = io.ReadFull(c, pb); err != nil {
		return
	}
	return command, host, strconv.Itoa(int(binary.BigEndian.Uint16(pb))), nil
}

// socksConnect is the client side: it sends the host as a name so the
// upstream resolves it (remote DNS), or as an address when it is an IP.
func socksConnect(c net.Conn, host, port string) error {
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		return err
	}
	if resp[0] != 5 || resp[1] != 0 {
		return errors.New("upstream refused SOCKS5 no-auth")
	}
	pn, err := strconv.Atoi(port)
	if err != nil || pn < 1 || pn > 65535 {
		return errors.New("invalid port")
	}
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(append(req, 1), v4...)
		} else {
			req = append(append(req, 4), ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("host name too long")
		}
		req = append(append(req, 3, byte(len(host))), host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(pn))
	if _, err := c.Write(req); err != nil {
		return err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return err
	}
	if head[1] != 0 {
		return fmt.Errorf("upstream CONNECT failed (reply %d)", head[1])
	}
	var skip int
	switch head[3] {
	case 1:
		skip = 4 + 2
	case 4:
		skip = 16 + 2
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return err
		}
		skip = int(l[0]) + 2
	default:
		return errors.New("bad upstream reply")
	}
	_, err = io.CopyN(io.Discard, c, int64(skip))
	return err
}

// DialVia opens host:port through a SOCKS5 proxy at socksAddr.
func DialVia(ctx context.Context, socksAddr, host, port string, timeout time.Duration) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dctx, "tcp", socksAddr)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(dctx, func() { _ = conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := socksConnect(conn, host, port); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := dctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// resolve asks the trusted resolver. It waits a bounded time; the lookup keeps
// running detached and fills the cache for later attempts.
func (p *Proxy) resolve(ctx context.Context, resolver Resolver, host string) (string, error) {
	rctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := resolver(rctx, host)
	if err == nil && len(ips) > 0 {
		return ips[0], nil
	}
	if err == nil {
		err = errors.New("no address")
	}
	return "", err
}
