package front

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

func testCA(t *testing.T) *CA {
	t.Helper()
	ca, err := Create(t.TempDir(), PermittedDomains(DefaultFamilies()))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestCARefusesToReplaceAndLoads(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, []string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(dir, []string{"example.com"}); err == nil {
		t.Fatal("overwrote an existing CA")
	}
	if _, err := Create(t.TempDir(), nil); err == nil {
		t.Fatal("created an unconstrained CA")
	}
	ca, err := Load(dir)
	if err != nil || !ca.Permits("a.example.com") || ca.Permits("example.org") {
		t.Fatalf("load: %v", err)
	}
	other, err := Create(t.TempDir(), []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if ca.Fingerprint() == other.Fingerprint() || ca.key.Equal(other.key) {
		t.Fatal("independent local installations shared a CA/key")
	}
}

func TestCAIsNameConstrained(t *testing.T) {
	ca := testCA(t)
	// A browser verifying a leaf for a fronted site accepts it.
	l, err := ca.Leaf("www.youtube.com")
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(l.Certificate[0])
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "www.youtube.com", Roots: ca.Pool()}); err != nil {
		t.Fatalf("leaf for a fronted site rejected: %v", err)
	}
	// ktest itself refuses to issue outside the list.
	if _, err := ca.Leaf("bank.example"); err == nil {
		t.Fatal("issued outside the constraints")
	}
	// And a stolen key could not do better: a certificate for another name,
	// signed with the CA key, fails verification because of the constraints.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "bank.example"}, DNSNames: []string{"bank.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	forged, _ := x509.ParseCertificate(der)
	if _, err := forged.Verify(x509.VerifyOptions{DNSName: "bank.example", Roots: ca.Pool()}); err == nil {
		t.Fatal("a certificate outside the constraints verified")
	}
}

func TestFamilyMatchAndFrontsFile(t *testing.T) {
	fams := DefaultFamilies()
	for host, want := range map[string]string{
		"www.youtube.com": "google", "rr1---sn-x.googlevideo.com": "google", "i.ytimg.com": "google",
		"www.instagram.com": "meta", "www.reddit.com": "fastly", "pypi.org": "fastly", "example.com": "",
		"pbs.twimg.com": "twimg",
	} {
		got := ""
		if f := Lookup(fams, host); f != nil {
			got = f.Name
		}
		if got != want {
			t.Errorf("%s: family %q, want %q", host, got, want)
		}
	}
	if Lookup(fams, "10.10.34.1") != nil || Lookup(fams, "notyoutube.com") != nil {
		t.Fatal("IP or look-alike matched")
	}
	extra, err := ParseFronts("# c\nfastly www.example-front.test\ngoogle - @own\nmeta www.x.test @own\n")
	if err != nil {
		t.Fatal(err)
	}
	got := WithFronts(fams, extra)
	if g := byName(got, "fastly").Fronts[0]; g.SNI != "www.example-front.test" || g.Dial != "www.example-front.test" {
		t.Fatalf("fastly front %+v", g)
	}
	if g := byName(got, "google").Fronts[0]; g.SNI != "" || g.Dial != "" {
		t.Fatalf("google front %+v", g)
	}
	if g := byName(got, "meta").Fronts[0]; g.SNI != "www.x.test" || g.Dial != "" {
		t.Fatalf("meta front %+v", g)
	}
	if _, err := ParseFronts("onlyone"); err == nil {
		t.Fatal("bad line accepted")
	}
}

func TestChooseALPN(t *testing.T) {
	cases := []struct {
		host    string
		offered []string
		want    string
		fail    bool
	}{
		{"www.youtube.com", []string{"h2", "http/1.1"}, "h2", false},
		{"rr1.googlevideo.com", []string{"h2", "http/1.1"}, "http/1.1", false},
		{"rr1.googlevideo.com", []string{"h2"}, "", true}, // do not force h2 on an h1-only video edge
		{"www.youtube.com", []string{"http/1.1"}, "http/1.1", false},
		{"pbs.twimg.com", []string{"h2", "http/1.1"}, "http/1.1", false},
		{"www.youtube.com", []string{"mqtt"}, "", true},
		{"www.youtube.com", nil, "", false},
	}
	for _, c := range cases {
		g := Lookup(DefaultFamilies(), c.host)
		got, err := chooseALPN(g, c.host, c.offered)
		if (err != nil) != c.fail || strings.Join(got, ",") != c.want {
			t.Errorf("%v: got %v, %v", c, got, err)
		}
	}
}

// edge is a stand-in for a CDN edge: it answers with a certificate chain a
// "public" CA signed, whatever the SNI is, and echoes what it saw.
type edge struct {
	ln       net.Listener
	roots    *x509.CertPool
	sniSeen  atomic.Value
	alpnSeen atomic.Value
}

func startEdge(t *testing.T, names ...string) *edge {
	return startEdgeALPN(t, []string{"http/1.1"}, names...)
}

func startEdgeALPN(t *testing.T, alpn []string, names ...string) *edge {
	t.Helper()
	pub := &testPublicCA{}
	pub.init(t)
	cert := pub.issue(t, names...)
	e := &edge{roots: pub.pool}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   alpn,
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			e.sniSeen.Store(h.ServerName)
			e.alpnSeen.Store(strings.Join(h.SupportedProtos, ","))
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.ln = ln
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				body := "host=" + req.Host
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}()
		}
	}()
	return e
}

type testPublicCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func (p *testPublicCA) init(t *testing.T) {
	p.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "public test root"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &p.key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	p.cert, _ = x509.ParseCertificate(der)
	p.pool = x509.NewCertPool()
	p.pool.AddCert(p.cert)
}

func (p *testPublicCA) issue(t *testing.T, names ...string) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func publicResolver(context.Context, string) ([]string, error) { return []string{"93.184.216.34"}, nil }

// socksVia opens a TLS connection to host through the proxy, trusting pool.
func socksVia(t *testing.T, proxy, host string, pool *x509.CertPool) (*tls.Conn, error) {
	return socksViaProtos(t, proxy, host, pool, []string{"http/1.1"})
}

func socksViaProtos(t *testing.T, proxy, host string, pool *x509.CertPool, protos []string) (*tls.Conn, error) {
	c, err := smartproxy.DialVia(context.Background(), proxy, host, "443", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(c, &tls.Config{ServerName: host, RootCAs: pool, NextProtos: protos})
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	return conn, conn.Handshake()
}

func startProxy(t *testing.T, f *Fronter, events chan<- smartproxy.Event) string {
	t.Helper()
	p, err := smartproxy.New(smartproxy.Config{
		Upstreams: []smartproxy.Upstream{
			{Name: "dead", Addr: "127.0.0.1:1"}, // a path that always fails to connect
			f.Upstream(),
		},
		Stagger: 50 * time.Millisecond,
		OnEvent: func(e smartproxy.Event) {
			select {
			case events <- e:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go p.Serve(ctx, ln)
	return ln.Addr().String()
}

func TestFrontServesTheSiteWithADifferentSNI(t *testing.T) {
	ca := testCA(t)
	e := startEdge(t, "www.google.com", "www.gstatic.com")
	f := New(Config{
		CA: ca, Roots: e.roots, Resolve: publicResolver, HedgeDelay: 100 * time.Millisecond,
		dial: func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", e.ln.Addr().String())
		},
	})
	events := make(chan smartproxy.Event, 8)
	proxy := startProxy(t, f, events)

	conn, err := socksVia(t, proxy, "www.youtube.com", ca.Pool())
	if err != nil {
		t.Fatalf("application handshake: %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: www.youtube.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "host=www.youtube.com" {
		t.Fatalf("the edge saw %q", body)
	}
	if sni, _ := e.sniSeen.Load().(string); sni != "www.google.com" {
		t.Fatalf("the wire carried SNI %q, want the front www.google.com", sni)
	}
	if alpn, _ := e.alpnSeen.Load().(string); alpn != "http/1.1" {
		t.Fatalf("edge saw ALPN %q", alpn)
	}
	select {
	case ev := <-events:
		if ev.Path != Name || !ev.OK {
			t.Fatalf("event %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no race event")
	}
	if acc, _ := f.Stats(); acc != 1 {
		t.Fatalf("accepted = %d", acc)
	}
	// The relay observes the HTTP status on its independent upstream goroutine.
	// Receiving the client body does not order that goroutine's score update.
	// Wait for the actual observation rather than racing its bookkeeping.
	learnDeadline := time.Now().Add(2 * time.Second)
	for len(f.Learned()) == 0 && time.Now().Before(learnDeadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(f.Learned()) == 0 {
		t.Fatal("nothing learned after serving a complete HTTP response")
	}
}

// Google's video caches answer a fronted ClientHello without selecting an ALPN
// protocol. The application's own leg is HTTP/1.1 only, so that is a working
// connection, not a failed handshake; rejecting it tore down every YouTube
// media connection while the page (which negotiates h2) kept working.
func TestFrontAcceptsAnEdgeThatSelectsNoALPNForMedia(t *testing.T) {
	ca := testCA(t)
	e := startEdgeALPN(t, nil, "*.c.docs.google.com")
	f := New(Config{
		CA: ca, Roots: e.roots, Resolve: publicResolver, HedgeDelay: 30 * time.Millisecond,
		dial: func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", e.ln.Addr().String())
		},
	})
	proxy := startProxy(t, f, make(chan smartproxy.Event, 8))
	// A browser offers h2 and http/1.1; googlevideo is pinned to HTTP/1.1.
	conn, err := socksViaProtos(t, proxy, "rr1---sn-x.googlevideo.com", ca.Pool(), []string{"h2", "http/1.1"})
	if err != nil {
		t.Fatalf("a media cache that selects no ALPN must be usable: %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET /videoplayback HTTP/1.1\r\nHost: rr1---sn-x.googlevideo.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "host=rr1---sn-x.googlevideo.com" {
		t.Fatalf("the edge saw %q", body)
	}
	if alpn, _ := e.alpnSeen.Load().(string); alpn != "http/1.1" {
		t.Fatalf("edge saw ALPN %q", alpn)
	}
}

// The allowance is only for a connection that asked for HTTP/1.1 alone: a page
// that negotiated h2 must still see a real h2 selection.
func TestFrontRejectsNoALPNWhenHTTP2WasOffered(t *testing.T) {
	ca := testCA(t)
	e := startEdgeALPN(t, nil, "www.google.com")
	f := New(Config{
		CA: ca, Roots: e.roots, Resolve: publicResolver, HedgeDelay: 30 * time.Millisecond,
		dial: func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", e.ln.Addr().String())
		},
	})
	proxy := startProxy(t, f, make(chan smartproxy.Event, 8))
	if conn, err := socksViaProtos(t, proxy, "www.youtube.com", ca.Pool(), []string{"h2", "http/1.1"}); err == nil {
		conn.Close()
		t.Fatal("an edge that cannot speak h2 was accepted for a page that asked for it")
	}
}

func TestFrontRejectsAnEdgeWithAnUntrustedCertificate(t *testing.T) {
	ca := testCA(t)
	e := startEdge(t, "attacker.example") // valid chain, but not for the site or its family
	f := New(Config{
		CA: ca, Roots: e.roots, Resolve: publicResolver, HedgeDelay: 50 * time.Millisecond,
		dial: func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", e.ln.Addr().String())
		},
	})
	proxy := startProxy(t, f, make(chan smartproxy.Event, 8))
	if conn, err := socksVia(t, proxy, "www.youtube.com", ca.Pool()); err == nil {
		conn.Close()
		t.Fatal("the application was answered although the edge's certificate was wrong")
	}
	if acc, ref := f.Stats(); acc != 0 || ref != 0 {
		t.Fatalf("the application must not even be touched (accepted %d, refused %d)", acc, ref)
	}
}

// A family whose every front dials a different machine has no route for a site
// that only its own servers can serve. That must fail at once instead of
// waiting for a result no front can produce.
func TestFrontWithoutAUsableRouteFailsFast(t *testing.T) {
	fam := &Family{
		Name: "media", Domains: []string{"media.example"},
		Fronts:    []Front{{SNI: "www.google.com", Dial: "www.google.com"}},
		NoStandIn: []string{"media.example"},
	}
	f := New(Config{Families: []Family{*fam}})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	if _, _, err := f.connect(ctx, []*Family{fam}, "media.example", []string{"http/1.1"}); err == nil {
		t.Fatal("a family with no usable front returned a connection")
	}
	if took := time.Since(started); took > time.Second {
		t.Fatalf("a family with no usable front waited %v instead of failing at once", took)
	}
}

func TestFrontFallsBackToTheNextFront(t *testing.T) {
	ca := testCA(t)
	e := startEdge(t, "www.google.com")
	var calls atomic.Int32
	f := New(Config{
		CA: ca, Roots: e.roots, HedgeDelay: 30 * time.Millisecond,
		Resolve: func(_ context.Context, name string) ([]string, error) {
			if name == "www.youtube.com" { // the first front uses the site's own address: poisoned
				return []string{"10.10.34.35"}, nil
			}
			return []string{"93.184.216.34"}, nil
		},
		dial: func(ctx context.Context, _ string) (net.Conn, error) {
			calls.Add(1)
			return (&net.Dialer{}).DialContext(ctx, "tcp", e.ln.Addr().String())
		},
	})
	proxy := startProxy(t, f, make(chan smartproxy.Event, 8))
	conn, err := socksVia(t, proxy, "www.youtube.com", ca.Pool())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	conn.Close()
	if calls.Load() == 0 {
		t.Fatal("never connected")
	}
}

func TestFrontSwitchesItselfOffWhenTheCAIsNotTrusted(t *testing.T) {
	ca := testCA(t)
	e := startEdge(t, "www.google.com")
	var trouble atomic.Int32
	f := New(Config{
		CA: ca, Roots: e.roots, Resolve: publicResolver, HedgeDelay: 30 * time.Millisecond,
		OnTrouble: func(string) { trouble.Add(1) },
		dial: func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", e.ln.Addr().String())
		},
	})
	proxy := startProxy(t, f, make(chan smartproxy.Event, 16))
	for i := 0; i < 4; i++ {
		// A refused destination is no longer retried. Independent destinations
		// still establish whether the CA is generally untrusted by this client.
		conn, err := socksVia(t, proxy, fmt.Sprintf("refusal-%d.youtube.com", i), x509.NewCertPool())
		if err == nil {
			conn.Close()
			t.Fatal("handshake unexpectedly succeeded")
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for f.Disabled() == "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if f.Disabled() == "" || trouble.Load() != 1 {
		t.Fatalf("disabled=%q trouble=%d", f.Disabled(), trouble.Load())
	}
	if f.handles("www.youtube.com") {
		t.Fatal("still claims the site after switching off")
	}
}

func TestProbeReportsEveryFront(t *testing.T) {
	e := startEdge(t, "www.google.com", "www.gstatic.com")
	f := New(Config{
		Roots: e.roots, Resolve: publicResolver,
		dial: func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", e.ln.Addr().String())
		},
	})
	res := f.Probe(context.Background(), "www.youtube.com", "/")
	if len(res) != len(DefaultFamilies()[0].Fronts) {
		t.Fatalf("%d results", len(res))
	}
	ok := 0
	for _, r := range res {
		if r.Err == nil && r.Status == 200 {
			ok++
		}
	}
	if ok == 0 {
		t.Fatalf("no front answered: %+v", res)
	}
}

func TestFrontUsesEdgeHintsWhenNoTrustedAddressExists(t *testing.T) {
	ca := testCA(t)
	e := startEdge(t, "www.microsoft.com", "www.facebook.com", "www.instagram.com")
	var dialed atomic.Value
	f := New(Config{
		CA: ca, Roots: e.roots, HedgeDelay: 30 * time.Millisecond,
		// Every name resolves to a block-page address: DNS is poisoned and DoH is dead.
		Resolve: func(context.Context, string) ([]string, error) { return []string{"10.10.34.36"}, nil },
		dial: func(ctx context.Context, addr string) (net.Conn, error) {
			dialed.Store(addr)
			return (&net.Dialer{}).DialContext(ctx, "tcp", e.ln.Addr().String())
		},
	})
	proxy := startProxy(t, f, make(chan smartproxy.Event, 8))
	conn, err := socksVia(t, proxy, "www.instagram.com", ca.Pool())
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	conn.Close()
	if addr, _ := dialed.Load().(string); !strings.HasPrefix(addr, "57.144.") {
		t.Fatalf("dialed %q, want one of the family's hints", addr)
	}
}

func byName(fams []Family, name string) Family {
	for _, f := range fams {
		if f.Name == name {
			return f
		}
	}
	panic("no family " + name)
}

func TestEdgeDefaultCertificateOfTheFamilyIsAccepted(t *testing.T) {
	ca := testCA(t)
	// A cache that answers www.google.com with its own default certificate.
	e := startEdge(t, "*.c.docs.google.com")
	f := New(Config{
		CA: ca, Roots: e.roots, HedgeDelay: 30 * time.Millisecond,
		Resolve: publicResolver,
		dial: func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", e.ln.Addr().String())
		},
	})
	proxy := startProxy(t, f, make(chan smartproxy.Event, 8))
	conn, err := socksVia(t, proxy, "rr1---sn-x.googlevideo.com", ca.Pool())
	if err != nil {
		t.Fatalf("a family-owned default certificate must be accepted: %v", err)
	}
	conn.Close()

	// A valid certificate for somebody else's name is still refused.
	other := startEdge(t, "*.attacker.example")
	f2 := New(Config{
		CA: ca, Roots: other.roots, HedgeDelay: 30 * time.Millisecond, Resolve: publicResolver,
		dial: func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", other.ln.Addr().String())
		},
	})
	proxy2 := startProxy(t, f2, make(chan smartproxy.Event, 8))
	if c, err := socksVia(t, proxy2, "rr1---sn-x.googlevideo.com", ca.Pool()); err == nil {
		c.Close()
		t.Fatal("a certificate for another owner was accepted")
	}
}
