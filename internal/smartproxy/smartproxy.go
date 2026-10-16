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
	"sync"
	"time"
)

// Upstream is a SOCKS5 proxy without authentication. An empty Addr is the
// ordinary system route (local DNS, no proxy).
type Upstream struct {
	Name string
	Addr string
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
	// Logf receives one line per decision; nil is silent.
	Logf func(format string, args ...any)
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

// Winners returns the remembered upstream per host (for display only).
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

// order lists upstreams: the remembered winner for the host first, then by
// wins (more is better) and average latency.
func (p *Proxy) order(host string) []*upstreamState {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := append([]*upstreamState(nil), p.ups...)
	remembered := ""
	if m, ok := p.mem[host]; ok && time.Since(m.at) < p.cfg.MemoryTTL {
		remembered = m.name
	}
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if (a.Name == remembered) != (b.Name == remembered) {
			return a.Name == remembered
		}
		if a.wins != b.wins {
			return a.wins > b.wins
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
		if m, has := p.mem[host]; has && m.name == u.Name {
			delete(p.mem, host)
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
	p.mem[host] = memo{name: u.Name, at: time.Now()}
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
	var up net.Conn
	var first []byte
	if isTLSFlight(flight) {
		up, first, err = p.race(ctx, host, port, flight)
	} else {
		up, err = p.plain(ctx, host, port, flight)
	}
	if err != nil {
		p.logf("%s:%s no path answered: %v", host, port, err)
		return
	}
	defer up.Close()
	if len(first) > 0 {
		if _, err := client.Write(first); err != nil {
			return
		}
	}
	pipe(client, up)
}

type outcome struct {
	u     *upstreamState
	conn  net.Conn
	first []byte
	took  time.Duration
	err   error
}

// race sends the TLS flight over the paths in learned order and returns the
// first connection that answered with a TLS handshake record.
func (p *Proxy) race(parent context.Context, host, port string, flight []byte) (net.Conn, []byte, error) {
	order := p.order(host)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	results := make(chan outcome, len(order))
	next, pending := 0, 0
	launch := func() {
		if next >= len(order) {
			return
		}
		u := order[next]
		next++
		pending++
		go func() {
			began := time.Now()
			conn, first, err := p.attempt(ctx, u, host, port, flight)
			results <- outcome{u, conn, first, time.Since(began), err}
		}()
	}
	launch()
	timer := time.NewTimer(p.cfg.Stagger)
	defer timer.Stop()
	var lastErr error
	for pending > 0 || next < len(order) {
		select {
		case <-parent.Done():
			go drain(results, pending)
			return nil, nil, parent.Err()
		case <-timer.C:
			launch()
			timer.Reset(p.cfg.Stagger)
		case r := <-results:
			pending--
			if r.err != nil {
				lastErr = fmt.Errorf("%s: %w", r.u.Name, r.err)
				p.record(r.u, host, false, r.took)
				p.logf("%s:%s %s failed: %v", host, port, r.u.Name, r.err)
				if pending == 0 {
					launch() // nothing in flight: do not wait for the stagger
				}
				continue
			}
			p.record(r.u, host, true, r.took)
			p.logf("%s:%s won by %s in %dms", host, port, r.u.Name, r.took.Milliseconds())
			cancel()
			go drain(results, pending)
			return r.conn, r.first, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream")
	}
	return nil, nil, lastErr
}

// drain closes connections of attempts that lost the race.
func drain(results <-chan outcome, pending int) {
	for ; pending > 0; pending-- {
		if r := <-results; r.conn != nil {
			_ = r.conn.Close()
		}
	}
}

// attempt connects through one upstream, sends the flight and requires a TLS
// handshake record back.
func (p *Proxy) attempt(ctx context.Context, u *upstreamState, host, port string, flight []byte) (net.Conn, []byte, error) {
	conn, err := p.dial(ctx, u.Upstream, host, port)
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	fail := func(err error) (net.Conn, []byte, error) {
		stop()
		_ = conn.Close()
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(p.cfg.FirstByteTimeout))
	if _, err := conn.Write(flight); err != nil {
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
		return nil, nil, context.Canceled
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, header, nil
}

// plain handles non-TLS traffic: no replay is possible, so use the best path
// and fall through only on connection failure.
func (p *Proxy) plain(ctx context.Context, host, port string, flight []byte) (net.Conn, error) {
	var lastErr error
	for _, u := range p.order(host) {
		conn, err := p.dial(ctx, u.Upstream, host, port)
		if err != nil {
			lastErr = err
			continue
		}
		if len(flight) > 0 {
			if _, err := conn.Write(flight); err != nil {
				_ = conn.Close()
				lastErr = err
				continue
			}
		}
		return conn, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no upstream")
	}
	return nil, lastErr
}

func (p *Proxy) dial(ctx context.Context, u Upstream, host, port string) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, p.cfg.ConnectTimeout)
	defer cancel()
	d := net.Dialer{}
	if u.Addr == "" {
		return d.DialContext(dctx, "tcp", net.JoinHostPort(host, port))
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
