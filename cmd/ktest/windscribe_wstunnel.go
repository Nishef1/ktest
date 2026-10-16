package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
	"github.com/Nishef1/ktest/internal/wstunnel"
)

// wsOptions configures the WStunnel bridge in Windscribe mode. Windscribe is
// set to OpenVPN TCP with ktest as its HTTP proxy; ktest re-wraps that OpenVPN
// stream the way Windscribe's own WStunnel protocol does, but with a chosen
// SNI, a browser TLS fingerprint and optionally through the user's own CDN
// hostname. The exit is always the Windscribe server: no other proxy or VPN
// sees the decrypted traffic.
type wsOptions struct {
	direct   bool
	sni      string // comma-separated SNIs for direct mode
	serverIP string // explicit WStunnel server IP; default: OpenVPN TCP IP - 1
	path     string
	cdnHost  string // user's CDN hostname whose origin is a Windscribe WStunnel IP
	cdnSNI   string
	cdnEdges string // comma-separated edge IPs or names
}

// defaultWindscribeSNIs are raced on the direct carriers: names a filtering
// SNI allowlist is likely to pass. The Windscribe node ignores the SNI.
const defaultWindscribeSNIs = "www.speedtest.net,www.digikala.com,www.aparat.com"

func (o wsOptions) enabled() bool { return o.direct || o.cdnHost != "" }

// describe names the WStunnel carriers for the connect summary.
func (o wsOptions) describe() string {
	var parts []string
	if o.cdnHost != "" {
		parts = append(parts, "CDN "+o.cdnHost)
	}
	if o.direct {
		parts = append(parts, "SNI "+strings.Join(splitList(o.sni), ","))
	}
	return "WStunnel/Stealth race (" + strings.Join(parts, "; ") + ")"
}

func validHostname(h string) bool {
	if h == "" || len(h) > 253 || net.ParseIP(h) != nil || strings.ContainsAny(h, "/:@ \t\r\n\\") || !strings.Contains(h, ".") {
		return false
	}
	return true
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (o wsOptions) validate() error {
	for _, s := range splitList(o.sni) {
		if !validHostname(s) {
			return fmt.Errorf("-windscribe-wstunnel-sni %q is not a hostname", s)
		}
	}
	if o.serverIP != "" {
		if ip := net.ParseIP(o.serverIP); ip == nil || ip.To4() == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return fmt.Errorf("-windscribe-wstunnel-ip %q must be a public IPv4 address", o.serverIP)
		}
	}
	if o.path != "" && (!strings.HasPrefix(o.path, "/tcp/127.0.0.1/") || strings.ContainsAny(o.path, " \r\n?#")) {
		return fmt.Errorf("-windscribe-wstunnel-path %q must look like /tcp/127.0.0.1/1194", o.path)
	}
	if o.cdnHost == "" {
		if o.cdnSNI != "" || o.cdnEdges != "" {
			return errors.New("-windscribe-cdn-sni and -windscribe-cdn-edge need -windscribe-cdn")
		}
		return nil
	}
	if strings.Contains(o.cdnHost, "://") || !validHostname(o.cdnHost) {
		return fmt.Errorf("-windscribe-cdn %q must be a bare hostname such as ws.example.com", o.cdnHost)
	}
	if o.cdnSNI != "" && !validHostname(o.cdnSNI) {
		return fmt.Errorf("-windscribe-cdn-sni %q is not a hostname", o.cdnSNI)
	}
	for _, e := range splitList(o.cdnEdges) {
		host := e
		if h, p, err := net.SplitHostPort(e); err == nil {
			if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("-windscribe-cdn-edge %q has a bad port", e)
			}
			host = h
		}
		if ip := net.ParseIP(host); ip != nil {
			if !ip.IsGlobalUnicast() || ip.IsPrivate() {
				return fmt.Errorf("-windscribe-cdn-edge %q must be a public address", e)
			}
		} else if !validHostname(host) {
			return fmt.Errorf("-windscribe-cdn-edge %q is neither an IP nor a hostname", e)
		}
	}
	return nil
}

// wsCarrier is one way to carry a Windscribe OpenVPN TCP stream.
type wsCarrier struct {
	name string
	open func(ctx context.Context, host, port string) (net.Conn, error)
}

// wsBridge decides, per HTTP CONNECT from Windscribe, how to carry it. Names
// (Windscribe API/DNS calls) keep the existing local anti-DPI dialer. An IP
// target is held until Windscribe's first bytes arrive: TLS/HTTP keeps the
// local dialer; OpenVPN is raced over every carrier and the first one whose
// Windscribe server answers that very packet carries the stream.
type wsBridge struct {
	opts    wsOptions
	path    string
	local   func(ctx context.Context, host, port string) (net.Conn, error)
	report  func(smartproxy.Event)
	logf    func(string, ...any)
	note    func(string, ...any) // always shown (edge scan progress)
	stagger time.Duration
	// candidates overrides the carrier list (tests).
	candidates func(host string) []wsCarrier

	mu    sync.Mutex
	edges []string                        // CDN edges found by the scan, best first
	good  map[string]string               // destination -> carrier that carried a working VPN
	bad   map[string]map[string]time.Time // destination -> carrier -> demoted until
}

// windscribeServerCert accepts only certificates naming a windscribe.com
// host, so the direct carriers can only ever end at a Windscribe server.
func windscribeServerCert(certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return errors.New("no certificate")
	}
	names := append([]string{certs[0].Subject.CommonName}, certs[0].DNSNames...)
	for _, n := range names {
		if strings.HasSuffix(strings.ToLower(n), ".windscribe.com") {
			return nil
		}
	}
	return errors.New("server is not a Windscribe node")
}

// neighbourIP returns ip+delta in the same /24. Windscribe numbers a node's
// addresses consecutively: WStunnel/IKEv2 = OpenVPN TCP - 1, Stealth/WireGuard
// = OpenVPN TCP + 1 (observed: 68.67.118.162/.163/.164, 198.44.157.27/.28/.29).
// The Windscribe certificate check and the OpenVPN answer confirm every guess.
func neighbourIP(openvpnIP string, delta int) (string, bool) {
	ip := net.ParseIP(openvpnIP).To4()
	if ip == nil {
		return "", false
	}
	last := int(ip[3]) + delta
	if last < 1 || last > 254 {
		return "", false
	}
	return net.IPv4(ip[0], ip[1], ip[2], byte(last)).String(), true
}

// wstunnelIP is the node's WStunnel address, or the explicit override.
func wstunnelIP(openvpnIP, override string) (string, bool) {
	if override != "" {
		return override, true
	}
	return neighbourIP(openvpnIP, -1)
}

func newWSBridge(o wsOptions, local func(context.Context, string, string) (net.Conn, error), report func(smartproxy.Event), logf func(string, ...any)) *wsBridge {
	path := o.path
	if path == "" {
		path = wstunnel.DefaultPath
	}
	b := &wsBridge{opts: o, path: path, local: local, report: report, logf: logf, note: logf, stagger: 250 * time.Millisecond,
		good: map[string]string{}, bad: map[string]map[string]time.Time{}}
	for _, e := range splitList(o.cdnEdges) {
		if _, _, err := net.SplitHostPort(e); err != nil {
			e = net.JoinHostPort(e, "443")
		}
		b.edges = append(b.edges, e)
	}
	return b
}

func directDial(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp", addr)
}

// carriersFor lists every way to reach the Windscribe node behind host, in
// launch order: CDN, WStunnel and Stealth per SNI (each straight and through
// local anti-DPI), then the raw OpenVPN stream through local anti-DPI.
func (b *wsBridge) carriersFor(host string) []wsCarrier {
	if b.candidates != nil {
		return b.candidates(host)
	}
	viaLocal := func(ctx context.Context, addr string) (net.Conn, error) {
		h, p, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		return b.local(ctx, h, p)
	}
	legs := []struct {
		suffix string
		dial   func(context.Context, string) (net.Conn, error)
	}{{"", directDial}, {" +anti-DPI", viaLocal}}
	var out []wsCarrier
	o := b.opts
	if o.cdnHost != "" {
		sni := o.cdnSNI
		if sni == "" {
			sni = o.cdnHost
		}
		b.mu.Lock()
		edges := append([]string(nil), b.edges...)
		b.mu.Unlock()
		if len(edges) == 0 {
			edges = []string{net.JoinHostPort(o.cdnHost, "443")}
		}
		if len(edges) > 3 {
			edges = edges[:3]
		}
		for _, leg := range legs {
			for _, edge := range edges {
				out = append(out, wsCarrier{name: "CDN " + o.cdnHost + "@" + edge + leg.suffix, open: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return wstunnel.Dial(ctx, wstunnel.Config{Addr: edge, SNI: sni, Host: o.cdnHost, Path: b.path, Verify: true, Dial: leg.dial})
				}})
			}
		}
	}
	if o.direct {
		snis := splitList(o.sni)
		if len(snis) == 0 {
			snis = []string{""}
		}
		ws, wsOK := wstunnelIP(host, o.serverIP)
		st, stOK := neighbourIP(host, +1)
		for _, leg := range legs {
			for _, sni := range snis {
				label := sni
				if label == "" {
					label = "none"
				}
				if wsOK {
					addr := net.JoinHostPort(ws, "443")
					out = append(out, wsCarrier{name: "WStunnel sni=" + label + leg.suffix, open: func(ctx context.Context, _, _ string) (net.Conn, error) {
						return wstunnel.Dial(ctx, wstunnel.Config{Addr: addr, SNI: sni, Host: ws, Path: b.path, VerifyPeer: windscribeServerCert, Dial: leg.dial})
					}})
				}
				if stOK {
					addr := net.JoinHostPort(st, "443")
					out = append(out, wsCarrier{name: "Stealth sni=" + label + leg.suffix, open: func(ctx context.Context, _, _ string) (net.Conn, error) {
						return wstunnel.DialStealth(ctx, wstunnel.Config{Addr: addr, SNI: sni, VerifyPeer: windscribeServerCert, Dial: leg.dial})
					}})
				}
			}
		}
	}
	return append(out, wsCarrier{name: "raw OpenVPN +anti-DPI", open: b.local})
}

// isWindscribeCarrier tells the live feed that a path name is a carrier.
func isWindscribeCarrier(path string) bool {
	for _, p := range []string{"CDN ", "WStunnel ", "Stealth ", "raw OpenVPN"} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// Dial is the HTTP bridge's dial function in Windscribe mode.
func (b *wsBridge) Dial(ctx context.Context, host, port string) (net.Conn, error) {
	if net.ParseIP(host) == nil {
		return b.local(ctx, host, port)
	}
	return newSniffConn(ctx, func(ctx context.Context, first []byte) (net.Conn, func(time.Duration, int64), error) {
		if looksTLSorHTTP(first) {
			c, err := b.local(ctx, host, port)
			if err == nil {
				if _, err = c.Write(first); err != nil {
					_ = c.Close()
				}
			}
			return c, nil, err
		}
		return b.race(ctx, host, port, first)
	}), nil
}

// looksTLSorHTTP tells Windscribe's API/HTTPS traffic from OpenVPN TCP,
// whose first bytes are a 2-byte length and a control opcode.
func looksTLSorHTTP(b []byte) bool {
	if len(b) >= 2 && b[0] == 0x16 && b[1] == 0x03 {
		return true
	}
	for _, m := range []string{"GET ", "POST", "HEAD", "PUT ", "CONN"} {
		if strings.HasPrefix(string(b), m) {
			return true
		}
	}
	return false
}

// ordered puts the carrier that last carried a working VPN first and
// carriers whose streams recently died early last.
func (b *wsBridge) ordered(key string, cs []wsCarrier) []wsCarrier {
	b.mu.Lock()
	defer b.mu.Unlock()
	good := b.good[key]
	var first, mid, last []wsCarrier
	for _, c := range cs {
		switch {
		case c.name == good:
			first = append(first, c)
		case time.Now().Before(b.bad[key][c.name]):
			last = append(last, c)
		default:
			mid = append(mid, c)
		}
	}
	return append(append(first, mid...), last...)
}

type raceResult struct {
	conn  net.Conn
	reply []byte
	c     wsCarrier
	took  time.Duration
}

// race sends Windscribe's first OpenVPN packet over every carrier, launched
// stagger apart, and keeps the first one the OpenVPN server answers. That
// answer (a tls-auth checked P_CONTROL_HARD_RESET_SERVER) proves the whole
// path works on this network right now, not only that a socket opened.
func (b *wsBridge) race(ctx context.Context, host, port string, first []byte) (net.Conn, func(time.Duration, int64), error) {
	key := net.JoinHostPort(host, port)
	cs := b.ordered(key, b.carriersFor(host))
	rctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	began := time.Now()
	var won sync.Once
	winner := make(chan raceResult, 1)
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var lastErr error
	fail := func(c wsCarrier, err error) {
		errMu.Lock()
		lastErr = fmt.Errorf("%s: %w", c.name, err)
		errMu.Unlock()
		b.logf("Windscribe %s: %s failed: %v", key, c.name, err)
	}
	for i, c := range cs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-rctx.Done():
				return
			case <-time.After(time.Duration(i) * b.stagger):
			}
			conn, err := c.open(rctx, host, port)
			if err != nil {
				if rctx.Err() == nil {
					fail(c, err)
				}
				return
			}
			stop := context.AfterFunc(rctx, func() { _ = conn.Close() })
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			buf := make([]byte, 2048)
			n := 0
			if _, err = conn.Write(first); err == nil {
				n, err = conn.Read(buf)
			}
			if n == 0 || !stop() {
				_ = conn.Close()
				if err == nil {
					err = errors.New("no answer")
				}
				if rctx.Err() == nil {
					fail(c, err)
				}
				return
			}
			_ = conn.SetDeadline(time.Time{})
			taken := false
			won.Do(func() {
				taken = true
				winner <- raceResult{conn: conn, reply: buf[:n], c: c, took: time.Since(began)}
			})
			if !taken {
				_ = conn.Close()
			}
		}()
	}
	go func() { wg.Wait(); close(winner) }()
	r, ok := <-winner
	cancel() // stops the losers
	if !ok {
		errMu.Lock()
		err := lastErr
		errMu.Unlock()
		if err == nil {
			err = errors.New("no carrier")
		}
		return nil, nil, fmt.Errorf("no Windscribe carrier answered: %w", err)
	}
	b.logf("Windscribe %s carried by %s; OpenVPN server answered in %s", key, r.c.name, shortDur(r.took))
	if b.report != nil {
		b.report(smartproxy.Event{Host: host, Site: host, Path: r.c.name, Took: r.took, TCPOnly: true})
	}
	done := func(lived time.Duration, received int64) {
		b.mu.Lock()
		defer b.mu.Unlock()
		switch {
		case lived >= time.Minute && received >= 64<<10:
			// The VPN came up and moved data: launch this carrier first next time.
			b.good[key] = r.c.name
		case lived < 20*time.Second:
			// Answered the first packet but died early (DPI reset, auth on a
			// wrong node): try the others first for ten minutes.
			if b.good[key] == r.c.name {
				delete(b.good, key)
			}
			if b.bad[key] == nil {
				b.bad[key] = map[string]time.Time{}
			}
			b.bad[key][r.c.name] = time.Now().Add(10 * time.Minute)
		}
	}
	return &prefixConn{Conn: r.conn, pending: r.reply}, done, nil
}

// prefixConn returns already-read bytes before reading the connection.
type prefixConn struct {
	net.Conn
	pending []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.pending) > 0 {
		n := copy(b, p.pending)
		p.pending = p.pending[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// scanCDNEdges looks for Cloudflare edges this network reaches that also
// carry the user's hostname to a WebSocket upgrade (HTTP 101), the way
// Shir-o-Khorshid scans CDN IPs for Psiphon's fronted hosts. It keeps the
// fastest few; until it finds one the hostname's own DNS answer is used.
func (b *wsBridge) scanCDNEdges(ctx context.Context, candidates []string) {
	o := b.opts
	sni := o.cdnSNI
	if sni == "" {
		sni = o.cdnHost
	}
	type found struct {
		addr string
		took time.Duration
	}
	jobs := make(chan string)
	results := make(chan found)
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				addr := net.JoinHostPort(ip, "443")
				began := time.Now()
				c, err := wstunnel.Dial(sctx, wstunnel.Config{Addr: addr, SNI: sni, Host: o.cdnHost, Path: b.path, Verify: true, Dial: directDial, Timeout: 6 * time.Second})
				if err != nil {
					continue
				}
				_ = c.Close()
				select {
				case results <- found{addr, time.Since(began)}:
				case <-sctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, ip := range candidates {
			select {
			case jobs <- ip:
			case <-sctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	var best []found
	for f := range results {
		best = append(best, f)
		slices.SortFunc(best, func(a, b found) int { return int(a.took - b.took) })
		addrs := make([]string, 0, len(best))
		for _, x := range best {
			addrs = append(addrs, x.addr)
		}
		b.mu.Lock()
		b.edges = addrs
		b.mu.Unlock()
		b.note("CDN edge %s carries %s to Windscribe (%s); %d found", f.addr, o.cdnHost, shortDur(f.took), len(best))
		if len(best) >= 6 {
			cancel()
		}
	}
	if len(best) == 0 && ctx.Err() == nil {
		b.note("No Cloudflare edge carried %s to a WebSocket upgrade; check the proxied DNS record and SSL mode Full", o.cdnHost)
	}
}

// sniffConn defers the real dial until the client's first write, so the
// carrier can be chosen from the protocol Windscribe actually speaks. open
// receives those first bytes and must send them itself.
type sniffConn struct {
	ctx   context.Context
	open  func(context.Context, []byte) (net.Conn, func(time.Duration, int64), error)
	ready chan struct{}
	once  sync.Once
	conn  net.Conn
	done  func(time.Duration, int64)
	err   error
	began time.Time
	read  int64

	mu        sync.Mutex
	deadlines [2]time.Time // read, write before the dial
	closed    bool
}

func newSniffConn(ctx context.Context, open func(context.Context, []byte) (net.Conn, func(time.Duration, int64), error)) *sniffConn {
	return &sniffConn{ctx: ctx, open: open, ready: make(chan struct{})}
}

// connect dials with first; it reports whether this call consumed first.
func (s *sniffConn) connect(first []byte) (used bool) {
	s.once.Do(func() {
		used = true
		defer close(s.ready)
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed {
			s.err = net.ErrClosed
			return
		}
		conn, done, err := s.open(s.ctx, first)
		if err != nil {
			s.err = err
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			s.err = net.ErrClosed
			return
		}
		s.conn, s.done, s.began = conn, done, time.Now()
		if !s.deadlines[0].IsZero() {
			_ = conn.SetReadDeadline(s.deadlines[0])
		}
		if !s.deadlines[1].IsZero() {
			_ = conn.SetWriteDeadline(s.deadlines[1])
		}
		s.mu.Unlock()
	})
	return used
}

func (s *sniffConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	used := s.connect(p)
	if s.err != nil {
		return 0, s.err
	}
	if used {
		return len(p), nil
	}
	return s.conn.Write(p)
}

func (s *sniffConn) Read(p []byte) (int, error) {
	<-s.ready
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.conn.Read(p)
	s.mu.Lock()
	s.read += int64(n)
	s.mu.Unlock()
	return n, err
}

func (s *sniffConn) Close() error {
	s.mu.Lock()
	s.closed = true
	conn, done, began, read := s.conn, s.done, s.began, s.read
	s.done = nil
	s.mu.Unlock()
	// Unblock a Read waiting for a write that will never come.
	s.once.Do(func() { s.err = net.ErrClosed; close(s.ready) })
	if conn == nil {
		return nil
	}
	if done != nil {
		done(time.Since(began), read)
	}
	return conn.Close()
}

func (s *sniffConn) setDeadline(i int, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		s.deadlines[i] = t
		if i == 0 && !t.IsZero() {
			// A Read still waiting for the first write must end too.
			time.AfterFunc(time.Until(t), func() {
				s.once.Do(func() { s.err = os.ErrDeadlineExceeded; close(s.ready) })
			})
		}
		return nil
	}
	if i == 0 {
		return s.conn.SetReadDeadline(t)
	}
	return s.conn.SetWriteDeadline(t)
}

func (s *sniffConn) SetReadDeadline(t time.Time) error  { return s.setDeadline(0, t) }
func (s *sniffConn) SetWriteDeadline(t time.Time) error { return s.setDeadline(1, t) }
func (s *sniffConn) SetDeadline(t time.Time) error {
	_ = s.setDeadline(0, t)
	return s.setDeadline(1, t)
}

type pendingAddr struct{}

func (pendingAddr) Network() string { return "tcp" }
func (pendingAddr) String() string  { return "pending" }

func (s *sniffConn) LocalAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return s.conn.LocalAddr()
	}
	return pendingAddr{}
}

func (s *sniffConn) RemoteAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return s.conn.RemoteAddr()
	}
	return pendingAddr{}
}

var _ io.ReadWriteCloser = (*sniffConn)(nil)
