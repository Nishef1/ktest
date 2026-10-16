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
//   - the CA is name-constrained to the fronted sites and lives in the user's
//     profile, so a leaked key cannot impersonate anything else;
//   - the upstream connection is made and verified first; the application is only
//     answered if that worked, so a failed front falls back to the other paths
//     with the application none the wiser;
//   - several fronts are learned per family (a server name open on one operator
//     is closed on the next), tried with hedging and remembered.
package front

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
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
	refused  int // consecutive refusals since the last accepted connection
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
		return []string{"h2"}, nil
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
			routes = append(routes, route{fam, fr})
		}
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
				f.note(r.rt.fam, r.rt.fr, true)
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
	ips, err := f.addrs(ctx, dialName)
	if err != nil && fr.Dial == "" && len(fam.Hints) > 0 {
		f.logf("front: no trusted address for %s (%v); using the family's edge hints", dialName, err)
		ips, err = shuffled(fam.Hints), nil
	}
	if err != nil {
		return nil, fmt.Errorf("address of %s: %w", dialName, err)
	}
	connect := func() (net.Conn, error) { return f.dialAny(ctx, ips) }
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
	if len(protos) == 1 && u.ConnectionState().NegotiatedProtocol != protos[0] {
		_ = raw.Close()
		return nil, fmt.Errorf("edge chose %q instead of %q", u.ConnectionState().NegotiatedProtocol, protos[0])
	}
	return u, nil
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
	f.refused = 0
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
		s.f.refusedOne()
		return fmt.Errorf("the application did not accept the ktest certificate (is the ktest CA trusted?): %w", err)
	}
	_ = client.SetDeadline(time.Time{})
	s.f.acceptedOne()
	relay(srv, s.up)
	return nil
}

type closeWriter interface{ CloseWrite() error }

// relay copies both directions and half-closes each when its source ends.
func relay(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	cp := func(dst io.WriteCloser, src io.Reader) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	_ = a.Close()
	_ = b.Close()
}

// ProbeResult is one front tested against one family without any certificate
// on the application's side.
type ProbeResult struct {
	Family string
	Site   string
	Front  Front
	Status int
	Took   time.Duration
	Err    error
}

// Probe fetches path from site through every front of its family, one request
// each, and reports what the edge answered. It needs no CA: it is the question
// "does this network let fronting through" asked before anything is installed.
func (f *Fronter) Probe(ctx context.Context, site, path string) []ProbeResult {
	fam := Lookup(f.cfg.Families, site)
	if fam == nil {
		return nil
	}
	fronts := append([]Front(nil), fam.Fronts...)
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
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("tcp connect: %w", last)
}
