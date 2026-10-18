// Package front implements domain fronting with a local, name-constrained
// certificate authority.
//
// The idea (from the public MITM-DomainFronting project, re-implemented here
// without Xray and improved): a censor that reads the SNI of a ClientHello
// decides by name. The application's own ClientHello can only be cut, not
// edited (any edit breaks the TLS transcript), but if ktest terminates the
// application's TLS itself it may open a brand-new connection to the CDN edge
// with an allowed server name, a browser-like fingerprint and the application's
// ALPN, and then relay the decrypted bytes. The edge routes by the Host header /
// :authority, not by the SNI, so the site that was asked for answers.
//
// What ktest adds over a plain MITM setup:
//   - the CA requests name constraints and lives in the user's profile;
//     trust-anchor handling differs across clients, so the CA key must still
//     be protected and removed when fronting is no longer needed;
//   - the upstream connection is made and verified first; the application is only
//     answered if that worked, so a failed front falls back to the other paths
//     with the application none the wiser;
//   - several fronts are learned per family (a server name open on one operator
//     is closed on the next), tried with hedging and remembered.
package front

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
	utls "github.com/refraction-networking/utls"
)

// Name is the path name shown in the live feed and summary.
const Name = "Front: domain fronting"

type Config struct {
	// CA signs the certificates presented to applications. It may be nil for
	// probing only.
	CA       *CA
	Families []Family
	// PreferredEdges prioritizes measured numeric public edges by family. A
	// provider control response is never evidence that a target works there.
	PreferredEdges map[string][]string
	// Resolve is the trusted resolver used for the address of a site or of a
	// front's Dial name.
	Resolve smartproxy.Resolver
	// Roots verifies the edge's certificate; nil means the system roots.
	Roots *x509.CertPool
	Logf  func(format string, args ...any)
	// DialTimeout bounds connect plus handshake of one front; HedgeDelay is how
	// long the best front is alone before the next one starts.
	DialTimeout time.Duration
	HedgeDelay  time.Duration
	// OnTrouble is called once when applications keep refusing the CA.
	OnTrouble func(msg string)
	// OnSession is called when a fronted connection ends, with what it carried.
	OnSession func(SessionInfo)
	// dial is replaceable in tests.
	dial func(ctx context.Context, addr string) (net.Conn, error)
}

type score struct{ ok, bad int }

// Fronter is the takeover path.
type Fronter struct {
	cfg Config

	mu       sync.Mutex
	scores   map[string]*score
	ech      map[string][]byte // learned ECH configurations by public name
	accepted int
	refused  int // total application refusals
	disabled string
}

func New(cfg Config) *Fronter {
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	if cfg.HedgeDelay <= 0 {
		cfg.HedgeDelay = 700 * time.Millisecond
	}
	if cfg.Families == nil {
		cfg.Families = DefaultFamilies()
	}
	preferred := make(map[string][]string, len(cfg.PreferredEdges))
	for family, ips := range cfg.PreferredEdges {
		for _, s := range ips {
			if ip := net.ParseIP(s); IsPublicEdgeIP(s) {
				preferred[family] = append(preferred[family], ip.String())
			}
		}
	}
	cfg.PreferredEdges = preferred
	if cfg.dial == nil {
		cfg.dial = func(ctx context.Context, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		}
	}
	return &Fronter{cfg: cfg, scores: map[string]*score{}}
}

func (f *Fronter) logf(format string, args ...any) {
	if f.cfg.Logf != nil {
		f.cfg.Logf(format, args...)
	}
}

// Upstream returns the path to add to the race.
func (f *Fronter) Upstream() smartproxy.Upstream {
	return smartproxy.Upstream{
		Name:     Name,
		Rank:     1,
		Match:    f.handles,
		Takeover: f.prepare,
	}
}

// MethodName identifies one frozen family/front strategy, including its wire
// SNI or real ECH public name. It does not depend on learned scores or edges.
func MethodName(family string, fr Front) string {
	sni, ech := fr.SNI, "off"
	if sni == "" {
		sni = "none"
	}
	if fr.ECH != "" {
		sni, ech = fr.ECH, fr.ECH
	}
	dial := fr.Dial
	if dial == "" {
		dial = "target"
	}
	return "Front: " + family + "; SNI=" + sni + "; ECH=" + ech + "; dial=" + dial
}

// Upstreams is the Android calibration surface: one deterministic candidate per
// family/front strategy. Takeover prepares exactly that strategy, never a race
// over different fronts. Windows consumers retain Upstream's learned race.
func (f *Fronter) Upstreams() []smartproxy.Upstream {
	var out []smartproxy.Upstream
	seen := map[string]bool{}
	protected, _ := smartproxy.NewAIDomainRules("")
	for _, family := range f.cfg.Families {
		fam := family
		for _, front := range fam.Fronts {
			fr := front
			method := MethodName(fam.Name, fr)
			if seen[method] {
				continue
			}
			seen[method] = true
			allowed := func(host string) bool {
				return f.cfg.CA != nil && f.cfg.CA.ValidAt(time.Now()) && f.cfg.CA.Permits(host) && fam.Match(host) &&
					!protected.Match(host) && !(fr.Dial != "" && fam.noStandIn(host)) && f.Disabled() == ""
			}
			out = append(out, smartproxy.Upstream{
				Name: method, Rank: 1, Match: allowed,
				Takeover: func(ctx context.Context, host, port string, flight []byte) (smartproxy.Session, error) {
					if !allowed(host) || port != "443" {
						return nil, errors.New("target is outside this front strategy or CA permissions")
					}
					sni, offered, ok := smartproxy.ParseClientHello(flight)
					name := normalize(sni)
					if !ok || name == "" || name != normalize(host) || !allowed(name) {
						return nil, errors.New("ClientHello does not match the permitted fronting target")
					}
					protos, err := chooseALPN(&fam, name, offered)
					if err != nil {
						return nil, err
					}
					conn, err := f.try(ctx, &fam, fr, name, protos)
					if err != nil {
						return nil, err
					}
					return &session{f: f, up: conn, name: name, protos: protos, fam: &fam, fr: fr}, nil
				},
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (f *Fronter) handles(host string) bool {
	if f.cfg.CA == nil {
		return false
	}
	fam := Lookup(f.cfg.Families, host)
	return fam != nil && f.cfg.CA.Permits(host) && f.Disabled() == ""
}

// Disabled is non-empty once ktest has given up fronting, with the reason.
func (f *Fronter) Disabled() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.disabled
}

// Stats reports how many fronted connections applications accepted and refused.
func (f *Fronter) Stats() (accepted, refused int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.accepted, f.refused
}

// Learned lists the fronts that worked, best first, as "family: front".
func (f *Fronter) Learned() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	type row struct {
		key string
		ok  int
	}
	var rows []row
	for k, s := range f.scores {
		if s.ok > 0 {
			rows = append(rows, row{k, s.ok})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ok > rows[j].ok })
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, strings.Replace(r.key, "|", ": ", 1))
	}
	return out
}

func frontKey(fam *Family, fr Front) string {
	return fam.Name + "|" + fr.String()
}

// ordered sorts a family's fronts by their track record on this network.
func (f *Fronter) ordered(fam *Family) []Front {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := append([]Front(nil), fam.Fronts...)
	rate := func(fr Front) int {
		s := f.scores[frontKey(fam, fr)]
		if s == nil {
			return 5
		}
		return int(10*(float64(s.ok)+1)/(float64(s.ok+s.bad)+2) + 0.5)
	}
	sort.SliceStable(list, func(i, j int) bool { return rate(list[i]) > rate(list[j]) })
	return list
}

func (f *Fronter) note(fam *Family, fr Front, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.scores[frontKey(fam, fr)]
	if s == nil {
		s = &score{}
		f.scores[frontKey(fam, fr)] = s
	}
	if ok {
		s.ok++
	} else {
		s.bad++
	}
}

// chooseALPN picks the one protocol to speak on both legs.
func chooseALPN(fam *Family, name string, offered []string) ([]string, error) {
	has := func(p string) bool {
		for _, o := range offered {
			if o == p {
				return true
			}
		}
		return false
	}
	switch {
	case len(offered) == 0:
		return nil, nil
	case has("h2") && !fam.h1Only(name):
		return []string{"h2"}, nil
	case has("http/1.1"):
		return []string{"http/1.1"}, nil
	case has("h2"):
		return nil, fmt.Errorf("%s needs HTTP/1.1 through this front, but client offered %v", name, offered)
	}
	return nil, fmt.Errorf("application protocol %v is not HTTP", offered)
}

// prepare reaches the site through the best front and returns a session that
// is ready to answer the application.
func (f *Fronter) prepare(ctx context.Context, host, port string, flight []byte) (smartproxy.Session, error) {
	if reason := f.Disabled(); reason != "" {
		return nil, errors.New(reason)
	}
	if f.cfg.CA == nil {
		return nil, errors.New("no CA")
	}
	if port != "443" {
		return nil, errors.New("only port 443")
	}
	sni, offered, ok := smartproxy.ParseClientHello(flight)
	if !ok {
		return nil, errors.New("unreadable ClientHello")
	}
	name := normalize(sni)
	if name == "" || net.ParseIP(name) != nil {
		name = normalize(host)
	}
	fams := LookupAll(f.cfg.Families, name)
	if len(fams) == 0 || !f.cfg.CA.Permits(name) {
		return nil, fmt.Errorf("%s is not a fronted site", name)
	}
	protos, err := chooseALPN(fams[0], name, offered)
	if err != nil {
		return nil, err
	}
	conn, rt, err := f.connect(ctx, fams, name, protos)
	if err != nil {
		return nil, err
	}
	f.logf("front: %s reached with %s", name, rt.fr)
	return &session{f: f, up: conn, name: name, protos: protos, fam: rt.fam, fr: rt.fr}, nil
}

// route is one way in: a front of one family.
type route struct {
	fam *Family
	fr  Front
}

type attemptResult struct {
	conn net.Conn
	rt   route
	err  error
}

// connect tries the fronts of every family that covers the site, the best one
// first and the next ones after a short delay or at once when the earlier one
// failed, and returns the first verified connection.
func (f *Fronter) connect(ctx context.Context, fams []*Family, name string, protos []string) (net.Conn, route, error) {
	var routes []route
	for _, fam := range fams {
		for _, fr := range f.ordered(fam) {
			if fr.Dial != "" && fam.noStandIn(name) {
				continue
			}
			routes = append(routes, route{fam, fr})
		}
	}
	if len(routes) == 0 {
		// Every front of the family dials another machine, and this site may only
		// be served by its own. Without this the waiter below would block on a
		// result that can never arrive until the caller's timeout.
		return nil, route{}, fmt.Errorf("%s: no usable front for this site", name)
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan attemptResult, len(routes))
	launched := 0
	launch := func() {
		if launched >= len(routes) {
			return
		}
		rt := routes[launched]
		launched++
		go func() {
			c, err := f.try(cctx, rt.fam, rt.fr, name, protos)
			results <- attemptResult{c, rt, err}
		}()
	}
	closeLosers := func(left int) {
		for ; left > 0; left-- {
			if x := <-results; x.conn != nil {
				_ = x.conn.Close()
			}
		}
	}
	launch()
	timer := time.NewTimer(f.cfg.HedgeDelay)
	defer timer.Stop()
	pending := 1
	var lastErr error
	for pending > 0 {
		select {
		case <-timer.C:
			if launched < len(routes) {
				launch()
				pending++
				timer.Reset(f.cfg.HedgeDelay)
			}
		case r := <-results:
			pending--
			if r.err == nil {
				// TLS success is not proof of application HTTP delivery.
				cancel()
				go closeLosers(pending)
				return r.conn, r.rt, nil
			}
			if ctx.Err() == nil {
				f.note(r.rt.fam, r.rt.fr, false)
			}
			lastErr = fmt.Errorf("%s: %w", r.rt.fr, r.err)
			f.logf("front: %s %v", name, lastErr)
			if launched < len(routes) {
				launch()
				pending++
			}
		case <-ctx.Done():
			go closeLosers(pending)
			return nil, route{}, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no front")
	}
	return nil, route{}, lastErr
}

// addrs returns the addresses to connect to for a name, never a block-page one.
func (f *Fronter) addrs(ctx context.Context, name string) ([]string, error) {
	if ip := net.ParseIP(name); ip != nil {
		return []string{name}, nil
	}
	if f.cfg.Resolve == nil {
		ips, err := net.DefaultResolver.LookupHost(ctx, name)
		if err != nil {
			return nil, err
		}
		return f.clean(ips)
	}
	ips, err := f.cfg.Resolve(ctx, name)
	if err != nil {
		return nil, err
	}
	return f.clean(ips)
}

func (f *Fronter) clean(ips []string) ([]string, error) {
	var out []string
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip != nil && !smartproxy.Bogus(ip) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, smartproxy.ErrPoisoned
	}
	return out, nil
}

// try makes one verified connection to the edge using one front.
func (f *Fronter) try(ctx context.Context, fam *Family, fr Front, name string, protos []string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, f.cfg.DialTimeout)
	defer cancel()
	dialName := fr.Dial
	if dialName == "" {
		dialName = name
	}
	if preferred := f.cfg.PreferredEdges[fam.Name]; len(preferred) > 0 {
		// Measured edges must get their attempt before a blocked resolver can
		// consume the budget. A failed target TLS handshake can still fall back
		// to the ordinary resolver/hints without changing front strategy.
		conn, err := f.tryOnIPs(ctx, fam, fr, name, protos, preferred, nil)
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, err
		}
	}
	ips, err := f.addrs(ctx, dialName)
	if err != nil && fr.Dial == "" && len(fam.Hints) > 0 {
		f.logf("front: no trusted address for %s (%v); using the family's edge hints", dialName, err)
		ips, err = shuffled(fam.Hints), nil
	}
	if err != nil {
		return nil, fmt.Errorf("address of %s: %w", dialName, err)
	}
	return f.tryOnIPs(ctx, fam, fr, name, protos, ips, nil)
}

// tryOnIPs shares the verified TLS/ECH protocol with ordinary fronting. The
// optional evidence belongs to one attempt, including ECH retry connections.
func (f *Fronter) tryOnIPs(ctx context.Context, fam *Family, fr Front, name string, protos, ips []string, tcpConnected *bool) (net.Conn, error) {
	connect := func() (net.Conn, error) {
		c, err := f.dialAny(ctx, ips)
		if err == nil && tcpConnected != nil {
			*tcpConnected = true
		}
		return c, err
	}
	if fr.ECH != "" {
		return f.tryECH(ctx, fr, name, protos, connect)
	}
	raw, err := connect()
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	conf := &utls.Config{
		ServerName:            fr.SNI,
		InsecureSkipVerify:    true, // replaced by VerifyPeerCertificate below
		VerifyPeerCertificate: f.verifier(fam, name, fr),
		MinVersion:            tls.VersionTLS12,
	}
	u := utls.UClient(raw, conf, utls.HelloChrome_Auto)
	if err := u.BuildHandshakeState(); err != nil {
		stop()
		_ = raw.Close()
		return nil, err
	}
	setALPN(u, protos)
	if err := u.HandshakeContext(ctx); err != nil {
		stop()
		_ = raw.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	if !stop() {
		_ = raw.Close()
		return nil, context.Canceled
	}
	if got := u.ConnectionState().NegotiatedProtocol; len(protos) == 1 && got != protos[0] && !noALPNIsHTTP1(protos, got) {
		_ = raw.Close()
		return nil, fmt.Errorf("edge chose %q instead of %q", got, protos[0])
	}
	return u, nil
}

// noALPNIsHTTP1 reports whether an edge that selected no ALPN is still usable.
// When HTTP/1.1 was the only protocol offered, an empty selection means the
// edge speaks HTTP/1.1 without ALPN: that is what the application's own leg
// will negotiate, and it is a working connection, not a rejected handshake.
// Google's video caches answer a fronted ClientHello (SNI www.google.com) this
// way; rejecting it tore down every YouTube media connection while the page,
// which negotiates h2, kept working.
func noALPNIsHTTP1(protos []string, got string) bool {
	return got == "" && len(protos) == 1 && protos[0] == "http/1.1"
}

// setALPN makes the ClientHello offer exactly the protocols the application
// negotiated, whatever the browser profile would have offered.
func setALPN(u *utls.UConn, protos []string) {
	exts := u.Extensions[:0]
	for _, e := range u.Extensions {
		switch x := e.(type) {
		case *utls.ALPNExtension:
			if len(protos) == 0 {
				continue
			}
			x.AlpnProtocols = protos
		case *utls.ApplicationSettingsExtension:
			if len(protos) == 0 {
				continue
			}
			x.SupportedProtocols = protos
		}
		exts = append(exts, e)
	}
	u.Extensions = exts
}

// verifier checks the edge's certificate chain against the root store for the
// front's own name, the site's name and the family's names. Fronting to an edge
// that returns its default certificate cannot use the requested name, which is
// why a list is checked; the chain must still be a valid public one.
func (f *Fronter) verifier(fam *Family, name string, fr Front) func([][]byte, [][]*x509.Certificate) error {
	candidates := []string{name}
	if fr.SNI != "" {
		candidates = append(candidates, fr.SNI)
	}
	if fr.Dial != "" {
		candidates = append(candidates, fr.Dial)
	}
	candidates = append(candidates, fam.Verify...)
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("no certificate")
		}
		certs := make([]*x509.Certificate, 0, len(raw))
		for _, r := range raw {
			c, err := x509.ParseCertificate(r)
			if err != nil {
				return err
			}
			certs = append(certs, c)
		}
		inter := x509.NewCertPool()
		for _, c := range certs[1:] {
			inter.AddCert(c)
		}
		var firstErr error
		for _, n := range candidates {
			_, err := certs[0].Verify(x509.VerifyOptions{DNSName: n, Roots: f.cfg.Roots, Intermediates: inter})
			if err == nil {
				return nil
			}
			if firstErr == nil {
				firstErr = err
			}
		}
		// An edge answers with its default certificate when the SNI is not one it
		// serves (a googlevideo cache returns *.c.docs.google.com for www.google.com).
		// That is still the family's own: a certificate from a public CA whose every
		// name lies inside the family's domains.
		if _, err := certs[0].Verify(x509.VerifyOptions{Roots: f.cfg.Roots, Intermediates: inter}); err == nil && namesWithin(certs[0], fam.Domains) {
			return nil
		}
		return fmt.Errorf("certificate not valid for the site or its family: %w", firstErr)
	}
}

// refusedOne records that an application did not accept the CA's certificate.
// Several in a row without a single accepted connection mean the CA is not
// trusted where the application looks; fronting then switches itself off so
// that every site works through the other paths instead of showing errors.
func (f *Fronter) refusedOne() {
	f.mu.Lock()
	f.refused++
	trouble := f.accepted == 0 && f.refused >= 3 && f.disabled == ""
	if trouble {
		f.disabled = "applications do not trust the ktest CA"
	}
	f.mu.Unlock()
	if trouble && f.cfg.OnTrouble != nil {
		f.cfg.OnTrouble("applications keep refusing the ktest certificate; fronting is off until it is trusted (ktest ca)")
	}
}

func (f *Fronter) acceptedOne() {
	f.mu.Lock()
	f.accepted++
	f.mu.Unlock()
}

type session struct {
	f      *Fronter
	up     net.Conn
	name   string
	protos []string
	fam    *Family
	fr     Front
}

// SessionInfo describes one finished fronted connection. A connection that
// carried requests upward but received nothing back is the sign of a front that
// connects and verifies but does not serve the site.
type SessionInfo struct {
	Host  string
	Front string
	Up    int64
	Down  int64
	Took  time.Duration
}

func (s *session) Close() { _ = s.up.Close() }

// replayConn presents bytes that were already read from the application ahead
// of the rest of the stream, so tls.Server can read the ClientHello again.
type replayConn struct {
	net.Conn
	pre []byte
}

func (c *replayConn) Read(p []byte) (int, error) {
	if len(c.pre) > 0 {
		n := copy(p, c.pre)
		c.pre = c.pre[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (s *session) Serve(client net.Conn, flight []byte) error {
	defer s.up.Close()
	conf := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: s.protos,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.f.cfg.CA.Leaf(s.name)
		},
	}
	srv := tls.Server(&replayConn{Conn: client, pre: flight}, conf)
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	if err := srv.Handshake(); err != nil {
		if clientAborted(err) {
			// Browsers open speculative connections and drop them unused; that is
			// not a refusal of the certificate.
			return nil
		}
		s.f.refusedOne()
		return fmt.Errorf("the application did not accept the ktest certificate (is the ktest CA trusted?): %w", err)
	}
	_ = client.SetDeadline(time.Time{})
	s.f.acceptedOne()
	began := time.Now()
	up, down, status := relayObserved(srv, s.up)
	if up > 0 && down > 0 && status != 0 {
		s.f.note(s.fam, s.fr, status >= 200 && status < 400)
	}
	if s.f.cfg.OnSession != nil {
		s.f.cfg.OnSession(SessionInfo{Host: s.name, Front: s.fr.String(), Up: up, Down: down, Took: time.Since(began)})
	}
	return nil
}

// clientAborted reports a handshake that ended because the application went
// away (closed, reset, timed out) rather than because it sent an alert about
// the certificate.
func clientAborted(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := err.Error()
	if strings.Contains(msg, "remote error") {
		return false // an alert: the application said why
	}
	for _, s := range []string{"EOF", "reset", "closed", "timeout", "broken pipe", "aborted"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

type closeWriter interface{ CloseWrite() error }

// relay copies both directions and half-closes each when its source ends.
// It returns the bytes that went to a (down, from b) and to b (up, from a).
// Only a bounded HTTP/1 response prefix is observed. The contents of
// requests, response headers and user data are never retained or logged.
type httpStatusPrefix struct{ first []byte }
func (p *httpStatusPrefix) Write(b []byte) (int, error) {
	if remaining := 32 - len(p.first); remaining > 0 {
		p.first = append(p.first, b[:min(len(b), remaining)]...)
	}
	return len(b), nil
}
func (p *httpStatusPrefix) status() int {
	if !strings.HasPrefix(string(p.first), "HTTP/1.1 ") && !strings.HasPrefix(string(p.first), "HTTP/1.0 ") {\n\t\treturn 0\n\t}
	var version string
	var code int
	if _, err := fmt.Sscanf(string(p.first), "%s %d", &version, &code); err != nil || code < 100 || code > 599 {\n\t\treturn 0\n\t}
	return code
}

// Existing callers retain the original byte-counting relay interface.
func relay(a, b io.ReadWriteCloser) (up, down int64) {
	up, down, _ = relayObserved(a, b)
	return
}

func relayObserved(a, b io.ReadWriteCloser) (up, down int64, status int) {
	done := make(chan struct{}, 2)
	cp := func(dst io.WriteCloser, src io.Reader, n *int64) {
		*n, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	var prefix httpStatusPrefix
	go cp(a, io.TeeReader(b, &prefix), &down)
	go cp(b, a, &up)
	<-done
	<-done
	_ = a.Close()
	_ = b.Close()
	return up, down, prefix.status()
}

// ProbeResult is one front tested against one family without any certificate
// on the application's side.
type ProbeResult struct {
	Family       string
	Site         string
	Front        Front
	Status       int
	Took         time.Duration
	Err          error
	TCPConnected bool
	TLSVerified  bool
	BodyBytes    int64
	BodyComplete bool
}

// IsPublicEdgeIP validates explicit comparison/preferred edges without DNS.
// Also exclude non-public special-purpose ranges not covered by Bogus.
func IsPublicEdgeIP(raw string) bool {
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || smartproxy.Bogus(net.ParseIP(ip.String())) {
		return false
	}
	for _, reserved := range []string{"192.0.0.0/24", "192.88.99.0/24", "198.18.0.0/15", "2001::/23", "2001:db8::/32", "3fff::/20", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64"} {
		if netip.MustParsePrefix(reserved).Contains(ip) {
			return false
		}
	}
	return true
}

// ProbeAtEdge requests the exact target path through each applicable strategy
// at one numeric public edge. It performs no MITM and needs no local CA. TLS,
// HTTP status and body transfer are separate evidence; none proves origin
// identity when fronting changes the verification name. No redirects follow.
func (f *Fronter) ProbeAtEdge(ctx context.Context, site, path, edgeIP string) []ProbeResult {
	var routes []route
	for _, fam := range LookupAll(f.cfg.Families, site) {
		for _, fr := range fam.Fronts {
			if fr.Dial != "" && fam.noStandIn(site) {
				continue
			}
			routes = append(routes, route{fam, fr})
		}
	}
	out := make([]ProbeResult, len(routes))
	ip := net.ParseIP(edgeIP)
	u, parseErr := url.ParseRequestURI(path)
	validPath := parseErr == nil && strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") && u.Host == "" && u.Scheme == "" && !strings.ContainsAny(path, "\r\n")
	var wg sync.WaitGroup
	for i, rt := range routes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			began := time.Now()
			r := ProbeResult{Family: rt.fam.Name, Site: site, Front: rt.fr}
			defer func() { r.Took = time.Since(began); out[i] = r }()
			if !IsPublicEdgeIP(edgeIP) || !validPath || strings.ContainsAny(site, "\r\n /:@") {
				r.Err = errors.New("probe requires a numeric public edge, hostname and origin-form HTTPS path")
				return
			}
			cctx, cancel := context.WithTimeout(ctx, f.cfg.DialTimeout)
			defer cancel()
			conn, err := f.tryOnIPs(cctx, rt.fam, rt.fr, site, []string{"http/1.1"}, []string{ip.String()}, &r.TCPConnected)
			if err != nil {
				r.Err = err
				return
			}
			r.TLSVerified = true
			defer conn.Close()
			stop := context.AfterFunc(cctx, func() { _ = conn.Close() })
			defer stop()
			if deadline, ok := cctx.Deadline(); ok {
				_ = conn.SetDeadline(deadline)
			}
			req, err := http.NewRequestWithContext(cctx, http.MethodGet, "https://"+site+path, nil)
			if err != nil {
				r.Err = err
				return
			}
			req.Close = true
			req.Header.Set("User-Agent", "KTest-Connectivity-Check/1.0")
			req.Header.Set("Cache-Control", "no-store")
			if err = req.Write(conn); err != nil {
				r.Err = err
				return
			}
			// Cap the whole response as well as the body. This prevents an edge
			// sending unbounded headers while preserving normal chunk framing.
			bounded := &io.LimitedReader{R: conn, N: 96 << 10}
			response, err := http.ReadResponse(bufio.NewReader(bounded), req)
			if err != nil {
				r.Err = err
				return
			}
			defer response.Body.Close()
			r.Status = response.StatusCode
			r.BodyBytes, err = io.Copy(io.Discard, io.LimitReader(response.Body, (64<<10)+1))
			r.BodyComplete = err == nil && r.BodyBytes <= 64<<10 && bounded.N > 0
			if err == nil && !r.BodyComplete {
				err = errors.New("response exceeds the diagnostic body/header limit")
			}
			r.Err = err
		}()
	}
	wg.Wait()
	return out
}

// Probe fetches path from site through every front of its family, one request
// each, and reports what the edge answered. It needs no CA: it is the question
// "does this network let fronting through" asked before anything is installed.
func (f *Fronter) Probe(ctx context.Context, site, path string) []ProbeResult {
	fam := Lookup(f.cfg.Families, site)
	if fam == nil {
		return nil
	}
	var fronts []Front
	for _, fr := range fam.Fronts {
		if fr.Dial != "" && fam.noStandIn(site) {
			continue
		}
		fronts = append(fronts, fr)
	}
	out := make([]ProbeResult, len(fronts))
	var wg sync.WaitGroup
	for i, fr := range fronts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			began := time.Now()
			r := ProbeResult{Family: fam.Name, Site: site, Front: fr}
			conn, err := f.try(ctx, fam, fr, site, []string{"http/1.1"})
			if err == nil {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(f.cfg.DialTimeout))
				r.Status, err = httpStatus(conn, site, path)
			}
			r.Err, r.Took = err, time.Since(began)
			out[i] = r
		}()
	}
	wg.Wait()
	return out
}

func httpStatus(c net.Conn, host, path string) (int, error) {
	req := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		return 0, err
	}
	buf := make([]byte, 64)
	n, err := io.ReadAtLeast(c, buf, 12)
	if err != nil {
		return 0, fmt.Errorf("no HTTP answer: %w", err)
	}
	line := string(buf[:n])
	var code int
	if _, err := fmt.Sscanf(line, "HTTP/1.1 %d", &code); err != nil {
		if _, err2 := fmt.Sscanf(line, "HTTP/1.0 %d", &code); err2 != nil {
			return 0, fmt.Errorf("not HTTP: %q", strings.TrimSpace(line))
		}
	}
	return code, nil
}

// dialAny connects to the first of up to four addresses that answers. The
// addresses are started 250 ms apart, so one dead or filtered address costs a
// quarter of a second instead of a whole timeout.
func (f *Fronter) dialAny(ctx context.Context, ips []string) (net.Conn, error) {
	if len(ips) > 4 {
		ips = ips[:4]
	}
	dctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, len(ips))
	launch := func(ip string) {
		go func() {
			c, err := f.cfg.dial(dctx, net.JoinHostPort(ip, "443"))
			ch <- res{c, err}
		}()
	}
	launched := 1
	launch(ips[0])
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	var last error
	for pending := 1; pending > 0; {
		select {
		case <-timer.C:
			if launched < len(ips) {
				launch(ips[launched])
				launched++
				pending++
				timer.Reset(250 * time.Millisecond)
			}
		case r := <-ch:
			pending--
			if r.err == nil {
				cancel()
				go func(left int) {
					for ; left > 0; left-- {
						if x := <-ch; x.c != nil {
							_ = x.c.Close()
						}
					}
				}(pending)
				return r.c, nil
			}
			last = r.err
			if launched < len(ips) {
				launch(ips[launched])
				launched++
				pending++
			}
		case <-ctx.Done():
			// Close whatever an in-flight dial still delivers after the cancel;
			// otherwise a timed-out front leaves a connected socket behind.
			go func(left int) {
				for ; left > 0; left-- {
					if x := <-ch; x.c != nil {
						_ = x.c.Close()
					}
				}
			}(pending)
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("tcp connect: %w", last)
}

// namesWithin reports whether the certificate has names and all of them (a
// wildcard counted by its suffix) are one of domains or below one.
func namesWithin(c *x509.Certificate, domains []string) bool {
	if len(c.DNSNames) == 0 {
		return false
	}
	for _, n := range c.DNSNames {
		n = strings.TrimPrefix(strings.ToLower(n), "*.")
		ok := false
		for _, d := range domains {
			if n == d || strings.HasSuffix(n, "."+d) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
