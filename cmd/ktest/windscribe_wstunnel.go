package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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

func (o wsOptions) enabled() bool { return o.direct || o.cdnHost != "" }

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
// target is held until Windscribe's first bytes arrive: TLS keeps the local
// dialer, anything else is OpenVPN TCP and goes through WStunnel carriers.
type wsBridge struct {
	carriers []wsCarrier
	local    func(ctx context.Context, host, port string) (net.Conn, error)
	report   func(smartproxy.Event)
	logf     func(string, ...any)

	mu   sync.Mutex
	next map[string]int // per destination: carrier index to try first
}

// windscribeServerCert accepts only certificates naming a windscribe.com
// host, so the direct carrier can only ever end at a Windscribe server.
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

// wstunnelIP derives the WStunnel server for an OpenVPN TCP address. On
// Windscribe nodes the IKEv2/WStunnel address sits one below the OpenVPN TCP
// address (observed: 68.67.118.163 -> .162, 198.44.157.28 -> .27). The
// Windscribe certificate check and HTTP 101 confirm every guess.
func wstunnelIP(openvpnIP, override string) (string, bool) {
	if override != "" {
		return override, true
	}
	ip := net.ParseIP(openvpnIP).To4()
	if ip == nil || ip[3] <= 1 {
		return "", false
	}
	prev := net.IPv4(ip[0], ip[1], ip[2], ip[3]-1)
	return prev.String(), true
}

func newWSBridge(o wsOptions, local func(context.Context, string, string) (net.Conn, error), report func(smartproxy.Event), logf func(string, ...any)) *wsBridge {
	b := &wsBridge{local: local, report: report, logf: logf, next: map[string]int{}}
	path := o.path
	if path == "" {
		path = wstunnel.DefaultPath
	}
	direct := func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp", addr)
	}
	viaLocal := func(ctx context.Context, addr string) (net.Conn, error) {
		h, p, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		return local(ctx, h, p)
	}
	legs := []struct {
		name string
		dial func(context.Context, string) (net.Conn, error)
	}{{"", direct}, {"+anti-DPI", viaLocal}}

	if o.cdnHost != "" {
		sni := o.cdnSNI
		if sni == "" {
			sni = o.cdnHost
		}
		edges := splitList(o.cdnEdges)
		if len(edges) == 0 {
			edges = []string{o.cdnHost}
		}
		for _, leg := range legs {
			for _, edge := range edges {
				addr := edge
				if _, _, err := net.SplitHostPort(edge); err != nil {
					addr = net.JoinHostPort(edge, "443")
				}
				name := fmt.Sprintf("wstunnel-cdn %s@%s%s", o.cdnHost, addr, leg.name)
				b.carriers = append(b.carriers, wsCarrier{name: name, open: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return wstunnel.Dial(ctx, wstunnel.Config{Addr: addr, SNI: sni, Host: o.cdnHost, Path: path, Verify: true, Dial: leg.dial})
				}})
			}
		}
	}
	if o.direct {
		snis := splitList(o.sni)
		if len(snis) == 0 {
			snis = []string{""}
		}
		for _, leg := range legs {
			for _, sni := range snis {
				label := sni
				if label == "" {
					label = "no SNI"
				}
				name := fmt.Sprintf("wstunnel-direct sni=%s%s", label, leg.name)
				b.carriers = append(b.carriers, wsCarrier{name: name, open: func(ctx context.Context, host, _ string) (net.Conn, error) {
					ws, ok := wstunnelIP(host, o.serverIP)
					if !ok {
						return nil, fmt.Errorf("no WStunnel address for %s", host)
					}
					return wstunnel.Dial(ctx, wstunnel.Config{Addr: net.JoinHostPort(ws, "443"), SNI: sni, Host: ws, Path: path, VerifyPeer: windscribeServerCert, Dial: leg.dial})
				}})
			}
		}
	}
	// Last resort: the unchanged raw OpenVPN TCP through local anti-DPI.
	b.carriers = append(b.carriers, wsCarrier{name: "raw OpenVPN via local anti-DPI", open: local})
	return b
}

// Dial is the HTTP bridge's dial function in Windscribe mode.
func (b *wsBridge) Dial(ctx context.Context, host, port string) (net.Conn, error) {
	if net.ParseIP(host) == nil {
		return b.local(ctx, host, port)
	}
	return newSniffConn(ctx, func(ctx context.Context, first []byte) (net.Conn, func(time.Duration, int64), error) {
		if looksTLSorHTTP(first) {
			c, err := b.local(ctx, host, port)
			return c, nil, err
		}
		return b.openTunnel(ctx, host, port)
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

// openTunnel tries carriers in order, starting where the previous attempt for
// this destination left off. A carrier that kept a stream up (a working VPN)
// stays first; one whose stream died early is skipped next time.
func (b *wsBridge) openTunnel(ctx context.Context, host, port string) (net.Conn, func(time.Duration, int64), error) {
	key := net.JoinHostPort(host, port)
	b.mu.Lock()
	start := b.next[key] % len(b.carriers)
	b.next[key] = (start + 1) % len(b.carriers) // reserve for concurrent CONNECTs
	b.mu.Unlock()
	var lastErr error
	for i := range b.carriers {
		idx := (start + i) % len(b.carriers)
		c := b.carriers[idx]
		began := time.Now()
		conn, err := c.open(ctx, host, port)
		if err != nil {
			lastErr = err
			b.logf("Windscribe %s: %s failed: %v", key, c.name, err)
			continue
		}
		b.mu.Lock()
		b.next[key] = (idx + 1) % len(b.carriers)
		b.mu.Unlock()
		b.logf("Windscribe %s carried by %s (VPN handshake not yet verified)", key, c.name)
		if b.report != nil {
			b.report(smartproxy.Event{Host: host, Site: host, Path: c.name, Took: time.Since(began), TCPOnly: true})
		}
		done := func(lived time.Duration, received int64) {
			// A VPN that stayed up for a minute and moved real data worked:
			// keep this carrier first for the next reconnect.
			if lived >= time.Minute && received >= 64<<10 {
				b.mu.Lock()
				b.next[key] = idx
				b.mu.Unlock()
			}
		}
		return conn, done, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no carrier")
	}
	return nil, nil, fmt.Errorf("all Windscribe carriers failed: %w", lastErr)
}

// sniffConn defers the real dial until the client's first write, so the
// carrier can be chosen from the protocol Windscribe actually speaks.
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

func (s *sniffConn) connect(first []byte) {
	s.once.Do(func() {
		defer close(s.ready)
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed {
			s.err = net.ErrClosed
			return
		}
		ctx, cancel := context.WithTimeout(s.ctx, 45*time.Second)
		defer cancel()
		conn, done, err := s.open(ctx, first)
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
}

func (s *sniffConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.connect(p)
	if s.err != nil {
		return 0, s.err
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
