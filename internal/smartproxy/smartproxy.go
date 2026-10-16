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
	// Stagger is how long the best path gets alone before the next one joins.
	Stagger time.Duration
	// ConnectTimeout bounds dial plus SOCKS handshake; FirstByteTimeout bounds
	// the wait for the server's first TLS record after the flight was sent.
	ConnectTimeout   time.Duration
	FirstByteTimeout time.Duration
	// MemoryTTL is how long a per-host winner is trusted first.
	MemoryTTL time.Duration
	// Resolve (A records) and Resolve6 (AAAA records) are used for LocalDNS
	// upstreams; nil leaves them on system DNS.
	Resolve  Resolver
	Resolve6 Resolver
	// Logf receives one line per decision; nil is silent.
	Logf func(format string, args ...any)
	// OnEvent is called once per raced connection with its outcome; it must
	// not block.
	OnEvent func(Event)
}

// Event is the outcome of one raced TLS connection.
type Event struct {
	Host string
	Site string // host reduced to the name the memory is keyed by
	Path string // winning path; empty when none answered
	Took time.Duration
	OK   bool
	Err  string // last failure reason when no path answered
	// Rejected marks a connection that a takeover path prepared but the
	// application then refused (it does not trust the certificate presented).
	Rejected bool
}

func (c *Config) defaults() {
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
	wins, fails int
	ewmaMS      float64
}

type memo struct {
	name string
	at   time.Time
}

type Proxy struct {
	cfg Config
	mu  sync.Mutex
	ups []*upstreamState
	mem map[string]memo
}

func New(cfg Config) (*Proxy, error) {
	if len(cfg.Upstreams) == 0 {
		return nil, errors.New("at least one upstream is required")
	}
	cfg.defaults()
	p := &Proxy{cfg: cfg, mem: map[string]memo{}}
	seen := map[string]bool{}
	for _, u := range cfg.Upstreams {
		if u.Name == "" || seen[u.Name] {
			return nil, fmt.Errorf("upstream names must be unique and non-empty (%q)", u.Name)
		}
		seen[u.Name] = true
		p.ups = append(p.ups, &upstreamState{Upstream: u})
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

// Winners returns the remembered upstream per site (for display only).
func (p *Proxy) Winners() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]string, len(p.mem))
	for h, m := range p.mem {
		if time.Since(m.at) < p.cfg.MemoryTTL {
			out[h] = m.name
		}
	}
	return out
}

// order lists upstreams: the remembered winner for the site first, then by
// success rate, static rank and average latency.
func (p *Proxy) order(host string) []*upstreamState {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := make([]*upstreamState, 0, len(p.ups))
	for _, u := range p.ups {
		if u.Match == nil || u.Match(host) {
			list = append(list, u)
		}
	}
	remembered := ""
	if m, ok := p.mem[siteKey(host)]; ok && time.Since(m.at) < p.cfg.MemoryTTL {
		remembered = m.name
	}
	// Success rate (smoothed, in tenths) rather than raw win counts: counting
	// wins makes whichever path won early win forever, even when every path is
	// equally good, and prefers noisy cut paths over the plain one.
	rate := func(u *upstreamState) int {
		return int(10*(float64(u.wins)+1)/(float64(u.wins+u.fails)+2) + 0.5)
	}
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if (a.Name == remembered) != (b.Name == remembered) {
			return a.Name == remembered
		}
		if ra, rb := rate(a), rate(b); ra != rb {
			return ra > rb
		}
		if a.Rank != b.Rank {
			return a.Rank < b.Rank
		}
		if a.ewmaMS != b.ewmaMS && a.ewmaMS != 0 && b.ewmaMS != 0 {
			return a.ewmaMS < b.ewmaMS
		}
		return false
	})
	return list
}

func (p *Proxy) record(u *upstreamState, host string, ok bool, took time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !ok {
		u.fails++
		if m, has := p.mem[siteKey(host)]; has && m.name == u.Name {
			delete(p.mem, siteKey(host))
		}
		return
	}
	u.wins++
	ms := float64(took.Milliseconds())
	if u.ewmaMS == 0 {
		u.ewmaMS = ms
	} else {
		u.ewmaMS = 0.8*u.ewmaMS + 0.2*ms
	}
	p.mem[siteKey(host)] = memo{name: u.Name, at: time.Now()}
}

// Serve accepts SOCKS5 clients until ctx ends.
func (p *Proxy) Serve(ctx context.Context, l net.Listener) error {
	go func() { <-ctx.Done(); _ = l.Close() }()
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
	host, port, err := socksRequest(client)
	if err != nil {
		return
	}
	// Success is announced before any upstream is known: a TLS client only
	// sends its ClientHello after this reply.
	if _, err := client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	flight := readFirstFlight(client)
	var win winner
	if isTLSFlight(flight) {
		host = p.nameFor(host, flight)
		win, err = p.race(ctx, host, port, flight)
	} else {
		win.conn, err = p.plain(ctx, host, port, flight)
	}
	if err != nil {
		p.logf("%s:%s no path answered: %v", host, port, err)
		return
	}
	if win.sess != nil {
		if err := win.sess.Serve(client, flight); err != nil {
			p.logf("%s:%s %s: %v", host, port, win.path, err)
			p.emit(Event{Host: host, Site: siteKey(host), Path: win.path, Err: err.Error(), Rejected: true})
		}
		return
	}
	defer win.conn.Close()
	if len(win.first) > 0 {
		if _, err := client.Write(win.first); err != nil {
			return
		}
	}
	pipe(client, win.conn)
}

// nameFor returns the name a connection is about: the SOCKS host, except when
// the application resolved the name itself and got a poisoned (private) answer,
// in which case the SNI of its ClientHello is the only truthful name left. This
// is what lets an application that ignores "proxy DNS" still work.
func (p *Proxy) nameFor(host string, flight []byte) string {
	ip := net.ParseIP(host)
	if ip == nil || !Bogus(ip) {
		return host
	}
	if sni, _, ok := ParseClientHello(flight); ok && sni != "" && net.ParseIP(sni) == nil {
		p.logf("%s is a block-page address; using the SNI %s instead", host, sni)
		return sni
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

// race sends the TLS flight in two waves. The first wave is one path: the one
// remembered for the site, else the best-ranked. If it does not answer within
// the stagger (longer when it is a remembered winner) or fails, the second wave
// starts every other path at once. One-by-one staggering would delay the right
// path of a blocked site by 300 ms for each path ranked above it.
func (p *Proxy) race(parent context.Context, host, port string, flight []byte) (winner, error) {
	order := p.order(host)
	if len(order) == 0 {
		return winner{}, errors.New("no path applies to this site")
	}
	// Late paths go to the back, behind a gate that opens when everything else
	// has failed or after lateAfter.
	remembered := p.rememberedName(host)
	var ordered, late []*upstreamState
	for _, u := range order {
		if u.Late && u.Name != remembered {
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
	wave := p.firstWave(order[0], host)
	launch(1)
	timer := time.NewTimer(wave)
	defer timer.Stop()
	lateGate := time.NewTimer(lateAfter)
	defer lateGate.Stop()
	var lastErr error
	for pending > 0 || next < len(order) {
		if pending == 0 && next >= limit && limit < len(order) {
			limit = len(order) // everything else failed: the last resort may go
			launch(-1)
		}
		select {
		case <-parent.Done():
			go drain(results, pending)
			return winner{}, parent.Err()
		case <-lateGate.C:
			limit = len(order)
			launch(-1)
		case <-timer.C:
			launch(-1)
		case r := <-results:
			pending--
			if r.err != nil {
				lastErr = fmt.Errorf("%s: %w", r.u.Name, r.err)
				p.record(r.u, host, false, r.took)
				p.logf("%s:%s %s failed: %v", host, port, r.u.Name, r.err)
				launch(-1) // the first wave failed: open the second at once
				continue
			}
			p.record(r.u, host, true, r.took)
			p.logf("%s:%s won by %s in %dms", host, port, r.u.Name, r.took.Milliseconds())
			p.emit(Event{Host: host, Site: siteKey(host), Path: r.u.Name, Took: r.took, OK: true})
			cancel()
			go drain(results, pending)
			r.win.path = r.u.Name
			return r.win, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream")
	}
	p.emit(Event{Host: host, Site: siteKey(host), Err: lastErr.Error()})
	return winner{}, lastErr
}

// lateAfter is how long a Late path waits behind the others at most.
const lateAfter = 3 * time.Second

// firstWave is how long the first path gets alone. It scales with that path's
// own typical time to a TLS record: on an open network the plain path then
// finishes before any duplicate flight is sent, while a blocked site still
// opens the second wave at once on a reset or after at most 1.5 s of silence.
func (p *Proxy) firstWave(first *upstreamState, host string) time.Duration {
	p.mu.Lock()
	typical := time.Duration(first.ewmaMS * 1.5 * float64(time.Millisecond))
	p.mu.Unlock()
	wave := max(p.cfg.Stagger, typical)
	if p.hasMemory(host) {
		wave = max(wave, 4*p.cfg.Stagger) // trust a learned path a little longer
	}
	return min(wave, 1500*time.Millisecond)
}

func (p *Proxy) emit(e Event) {
	if p.cfg.OnEvent != nil {
		p.cfg.OnEvent(e)
	}
}

// rememberedName is the path remembered for the site, or "".
func (p *Proxy) rememberedName(host string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if m, ok := p.mem[siteKey(host)]; ok && time.Since(m.at) < p.cfg.MemoryTTL {
		return m.name
	}
	return ""
}

func (p *Proxy) hasMemory(host string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	m, ok := p.mem[siteKey(host)]
	return ok && time.Since(m.at) < p.cfg.MemoryTTL
}

// siteKey reduces a host to the name the memory is keyed by, so that one win on
// r1---sn-abc.googlevideo.com speeds up every googlevideo.com node. It is an
// approximation of the registrable domain without a public-suffix list.
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

// attempt connects through one upstream, sends the flight and requires a TLS
// handshake record back.
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
	conn, err := p.dial(ctx, u.Upstream, host, port)
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
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fail(fmt.Errorf("no server response: %w", err))
	}
	if header[0] != 0x16 || header[1] != 3 {
		return fail(fmt.Errorf("not a TLS handshake record (type 0x%02x)", header[0]))
	}
	if !stop() { // ctx already ended, the race was decided elsewhere
		_ = conn.Close()
		return winner{}, context.Canceled
	}
	_ = conn.SetDeadline(time.Time{})
	return winner{conn: conn, first: header}, nil
}

// plain handles non-TLS traffic: no replay is possible and nothing cuts a
// protocol it cannot parse, so only the direct route and exit paths are tried,
// in learned order, falling through when the connection cannot be made. The
// outcome is remembered per destination, so a destination blocked by address
// (Telegram's) goes to the exit first the next time instead of timing out again.
func (p *Proxy) plain(ctx context.Context, host, port string, flight []byte) (net.Conn, error) {
	all := p.order(host)
	var cands []*upstreamState
	for _, u := range all {
		if u.Takeover == nil && (u.Addr == "" || u.Exit) {
			cands = append(cands, u)
		}
	}
	if len(cands) == 0 { // no direct or exit path configured: use whatever relays
		for _, u := range all {
			if u.Takeover == nil {
				cands = append(cands, u)
			}
		}
	}
	var lastErr error
	for _, u := range cands {
		began := time.Now()
		conn, err := p.dial(ctx, u.Upstream, host, port)
		if err == nil && len(flight) > 0 {
			if _, werr := conn.Write(flight); werr != nil {
				_ = conn.Close()
				conn, err = nil, werr
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			p.record(u, host, false, time.Since(began))
			lastErr = fmt.Errorf("%s: %w", u.Name, err)
			continue
		}
		p.record(u, host, true, time.Since(began))
		return conn, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream")
	}
	return nil, lastErr
}

// Add joins an upstream to the race while the proxy runs, for paths that take
// a while to come up (a tunnel that has to scan first).
func (p *Proxy) Add(u Upstream) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if u.Name == "" {
		return errors.New("upstream name is required")
	}
	for _, x := range p.ups {
		if x.Name == u.Name {
			return fmt.Errorf("upstream %q already exists", u.Name)
		}
	}
	p.ups = append(p.ups, &upstreamState{Upstream: u})
	return nil
}

func (p *Proxy) dial(ctx context.Context, u Upstream, host, port string) (net.Conn, error) {
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

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// readFirstFlight reads the client's first bytes. A TLS ClientHello is read
// completely (its record length is known); anything else returns what arrived
// within a short window, and an empty result means the server speaks first.
func readFirstFlight(c net.Conn) []byte {
	_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 16*1024)
	for {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf
		}
		if len(buf) >= 5 && buf[0] == 0x16 && buf[1] == 3 {
			if len(buf) >= 5+int(binary.BigEndian.Uint16(buf[3:5])) {
				return buf
			}
			continue
		}
		return buf
	}
}

func isTLSFlight(b []byte) bool {
	return len(b) >= 6 && b[0] == 0x16 && b[1] == 3 && b[5] == 0x01 // handshake, ClientHello
}

// socksRequest performs the server side of SOCKS5 (no authentication, CONNECT).
func socksRequest(c net.Conn) (host, port string, err error) {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	hdr := make([]byte, 2)
	if _, err = io.ReadFull(c, hdr); err != nil {
		return
	}
	if hdr[0] != 5 {
		return "", "", errors.New("not SOCKS5")
	}
	methods := make([]byte, hdr[1])
	if _, err = io.ReadFull(c, methods); err != nil {
		return
	}
	if !bytes.Contains(methods, []byte{0}) {
		_, _ = c.Write([]byte{5, 0xff})
		return "", "", errors.New("no acceptable auth method")
	}
	if _, err = c.Write([]byte{5, 0}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err = io.ReadFull(c, req); err != nil {
		return
	}
	if req[1] != 1 {
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return "", "", errors.New("only CONNECT is supported")
	}
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
		return "", "", errors.New("unsupported address type")
	}
	pb := make([]byte, 2)
	if _, err = io.ReadFull(c, pb); err != nil {
		return
	}
	return host, strconv.Itoa(int(binary.BigEndian.Uint16(pb))), nil
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
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := socksConnect(conn, host, port); err != nil {
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
