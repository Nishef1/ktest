package front

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

func TestFixedFrontUpstreamsNeverReraceStrategies(t *testing.T) {
	e := startEdge(t, "www.google.com", "www.gstatic.com")
	ca, err := Create(t.TempDir(), []string{"youtube.com", "google.com"})
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	f := New(Config{CA: ca, Roots: e.roots, Resolve: publicResolver, dial: func(ctx context.Context, addr string) (net.Conn, error) {
		attempts.Add(1)
		return (&net.Dialer{}).DialContext(ctx, "tcp", e.ln.Addr().String())
	}})
	ups := f.Upstreams()
	if len(ups) < 4 {
		t.Fatalf("missing fixed candidates: %d", len(ups))
	}
	seen := map[string]bool{}
	for _, up := range ups {
		if seen[up.Name] {
			t.Fatalf("duplicate method %s", up.Name)
		}
		seen[up.Name] = true
		if up.Match("x.com") || up.Match("youtube.com.evil.test") {
			t.Fatalf("method exceeds family/CA/policy: %s", up.Name)
		}
	}
	var selected smartproxy.Upstream
	for _, up := range ups {
		if up.Name == MethodName("google", Front{SNI: "www.google.com"}) {
			selected = up
		}
	}
	if selected.Takeover == nil || !selected.Match("www.youtube.com") {
		t.Fatal("own-edge Google strategy missing")
	}
	// Capture a real application ClientHello; the selected takeover must dial
	// exactly its declared SNI even when another strategy has a better score.
	for i := 0; i < 10; i++ {
		f.note(&f.cfg.Families[0], Front{SNI: "www.google.com", Dial: "www.google.com"}, true)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: "www.youtube.com", NextProtos: []string{"http/1.1"}}).Handshake()
	}()
	flight := make([]byte, 65536)
	n, err := server.Read(flight)
	if err != nil {
		t.Fatal(err)
	}
	s, err := selected.Takeover(context.Background(), "www.youtube.com", "443", flight[:n])
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if attempts.Load() != 1 || e.sniSeen.Load() != "www.google.com" {
		t.Fatalf("strategy reraced: attempts=%d SNI=%v", attempts.Load(), e.sniSeen.Load())
	}
	if _, err := selected.Takeover(context.Background(), "x.com", "443", flight[:n]); err == nil {
		t.Fatal("accepted different CONNECT host")
	}
}

func TestProbeAtEdgeReportsVerifiedHTTPBodyAndRefusal(t *testing.T) {
	for _, status := range []int{200, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			pub := &testPublicCA{}
			pub.init(t)
			cert := pub.issue(t, "www.google.com")
			var requestURI, host string
			ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				requestURI, host = req.RequestURI, req.Host
				fmt.Fprintf(c, "HTTP/1.1 %d Result\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello", status)
			}()
			f := New(Config{Families: []Family{{Name: "google", Domains: []string{"youtube.com"}, Fronts: []Front{{SNI: "www.google.com"}}}}, Roots: pub.pool, dial: func(ctx context.Context, addr string) (net.Conn, error) {
				if addr != "8.8.8.8:443" {
					t.Errorf("unpinned dial %s", addr)
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
			}})
			r := f.ProbeAtEdge(context.Background(), "www.youtube.com", "/watch?v=one%20two", "8.8.8.8")
			<-done
			if len(r) != 1 || r[0].Err != nil || !r[0].TCPConnected || !r[0].TLSVerified || r[0].Status != status || r[0].BodyBytes != 5 || !r[0].BodyComplete {
				t.Fatalf("false/missing evidence: %+v", r)
			}
			if requestURI != "/watch?v=one%20two" || host != "www.youtube.com" {
				t.Fatalf("request changed: %s %s", requestURI, host)
			}
		})
	}
}

func TestProbeAtEdgeRejectsUntrustedTLSAndUnsafeRequests(t *testing.T) {
	e := startEdge(t, "www.google.com")
	f := New(Config{DialTimeout: time.Second, dial: func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", e.ln.Addr().String())
	}})
	r := f.ProbeAtEdge(context.Background(), "www.youtube.com", "/", "8.8.8.8")
	for _, one := range r {
		if !one.TCPConnected || one.TLSVerified || one.Status != 0 || one.Err == nil {
			t.Fatalf("untrusted TLS accepted: %+v", one)
		}
	}
	f = New(Config{Families: []Family{{Name: "google", Domains: []string{"youtube.com"}, Fronts: []Front{{SNI: "www.google.com"}}}}, dial: func(context.Context, string) (net.Conn, error) {
		t.Error("invalid request opened a socket")
		return nil, fmt.Errorf("invalid request")
	}})
	// Invalid request data must fail before any socket is opened.
	for _, path := range []string{"/\r\nHost:evil", "https://evil.test/"} {
		r = f.ProbeAtEdge(context.Background(), "www.youtube.com", path, "8.8.8.8")
		if len(r) != 1 || r[0].TCPConnected || r[0].Err == nil {
			t.Fatalf("unsafe path accepted: %+v", r)
		}
	}
}

func TestProbeAtEdgeRequiresRealECHAcceptanceAndTargetCertificate(t *testing.T) {
	pub := &testPublicCA{}
	pub.init(t)
	cert := pub.issue(t, CloudflareECH, "api.x.com")
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	list := dummyECHConfig(CloudflareECH)
	copy(list[11:43], key.PublicKey().Bytes())
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS13, EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: list[2:], PrivateKey: key.Bytes(), SendAsRetry: true}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted atomic.Int32
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
				st := c.(*tls.Conn).ConnectionState()
				if st.ECHAccepted && st.ServerName == "api.x.com" && req.Host == "api.x.com" {
					accepted.Add(1)
				}
				fmt.Fprint(c, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
			}()
		}
	}()
	f := New(Config{Roots: pub.pool, dial: func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}})
	r := f.ProbeAtEdge(context.Background(), "api.x.com", "/2/users/me", "8.8.8.8")
	if len(r) != 1 || r[0].Err != nil || !r[0].TLSVerified || r[0].Status != 204 || !r[0].BodyComplete || accepted.Load() != 1 {
		t.Fatalf("real ECH not accepted: %+v accepted=%d", r, accepted.Load())
	}
	if len(f.echConfig(CloudflareECH)) == 0 {
		t.Fatal("verified ECH retry configuration was not learned")
	}
	// A poisoned resolver must not consume the entire deadline before an ECH
	// route can use its already-known edges. A silent TCP accept must not beat
	// the alternative that completes authenticated TLS for the actual API.
	var lookups atomic.Int32
	f.cfg.Resolve = func(ctx context.Context, _ string) ([]string, error) {
		lookups.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	f.cfg.PreferredEdges = map[string][]string{"cloudflare": {"8.8.8.8"}}
	f.cfg.HedgeDelay = 10 * time.Millisecond
	f.cfg.DialTimeout = 200 * time.Millisecond
	f.cfg.dial = func(ctx context.Context, address string) (net.Conn, error) {
		if address == "8.8.8.8:443" {
			client, server := net.Pipe()
			go func() { <-ctx.Done(); server.Close() }()
			return client, nil
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}
	fam := &Family{Name: "cloudflare", Domains: []string{"x.com"}, Hints: []string{"8.8.8.8", "8.8.4.4"}}
	conn, err := f.try(context.Background(), fam, Front{ECH: CloudflareECH}, "api.x.com", []string{"http/1.1"})
	if err != nil {
		t.Fatalf("working ECH API route lost to filtered DNS/silent TCP: %v", err)
	}
	conn.Close()
	if lookups.Load() != 0 {
		t.Fatal("known ECH edges waited for poisoned DNS")
	}
}

func TestProbeAtEdgeReportsIncompleteBody(t *testing.T) {
	pub := &testPublicCA{}
	pub.init(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pub.issue(t, "www.google.com")}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if _, err := http.ReadRequest(bufio.NewReader(c)); err == nil {
			fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort")
		}
	}()
	f := New(Config{Roots: pub.pool, Families: []Family{{Name: "google", Domains: []string{"youtube.com"}, Fronts: []Front{{SNI: "www.google.com"}}}}, dial: func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}})
	r := f.ProbeAtEdge(context.Background(), "www.youtube.com", "/", "8.8.8.8")
	if len(r) != 1 || !r[0].TLSVerified || r[0].Status != 200 || r[0].BodyComplete || r[0].BodyBytes != 5 || r[0].Err == nil {
		t.Fatalf("truncated body counted complete: %+v", r)
	}
}

func TestFixedFrontMetadataAndPreferredEdges(t *testing.T) {
	e := startEdge(t, "www.google.com")
	var dialed string
	f := New(Config{Roots: e.roots, Resolve: publicResolver, PreferredEdges: map[string][]string{"google": {"8.8.8.8"}}, dial: func(ctx context.Context, addr string) (net.Conn, error) {
		dialed = addr
		return (&net.Dialer{}).DialContext(ctx, "tcp", e.ln.Addr().String())
	}})
	c, err := f.try(context.Background(), &f.cfg.Families[0], Front{SNI: "www.google.com"}, "www.youtube.com", []string{"http/1.1"})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if dialed != "8.8.8.8:443" {
		t.Fatalf("preferred edge ignored: %s", dialed)
	}
	var ech bool
	for _, up := range f.Upstreams() {
		if strings.Contains(up.Name, "cloudflare") && strings.Contains(up.Name, "ECH="+CloudflareECH) {
			ech = true
		}
	}
	if !ech {
		t.Fatal("X ECH strategy missing from method metadata")
	}
}

func TestPreferredEdgesAreTriedBeforeBlockedDNS(t *testing.T) {
	e := startEdge(t, "www.google.com")
	f := New(Config{Roots: e.roots, DialTimeout: 100 * time.Millisecond, PreferredEdges: map[string][]string{"google": {"8.8.8.8"}}, Resolve: func(ctx context.Context, _ string) ([]string, error) { <-ctx.Done(); return nil, ctx.Err() }, dial: func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", e.ln.Addr().String())
	}})
	c, err := f.try(context.Background(), &f.cfg.Families[0], Front{SNI: "www.google.com"}, "www.youtube.com", []string{"http/1.1"})
	if err != nil {
		t.Fatalf("preferred measured edge waited for blocked DNS: %v", err)
	}
	c.Close()
}
