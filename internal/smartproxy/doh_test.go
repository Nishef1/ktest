package smartproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoHLearnsEndpointAndReusesTLSAcrossNames(t *testing.T) {
	var requests, dials atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, `{"Status":0,"Answer":[{"type":1,"TTL":60,"data":"142.250.1.1"}]}`)
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	endpoints := make([]DoHEndpoint, 9)
	for i := range endpoints {
		endpoints[i] = DoHEndpoint{URL: "https://example.com/resolve"}
	}
	r := NewDoH(endpoints, dial, pool)
	for i := 0; i < 20; i++ {
		if _, err := r(context.Background(), fmt.Sprintf("host%d.example", i)); err != nil {
			t.Fatal(err)
		}
	}
	if n := requests.Load(); n != 20 {
		t.Fatalf("fast healthy resolver caused %d queries for 20 names", n)
	}
	if n := dials.Load(); n > 2 {
		t.Fatalf("repeated resolver TLS setup: %d connections", n)
	}
	t.Logf("20 distinct names: %d queries, %d TLS connections", requests.Load(), dials.Load())
}

func TestDoHFallbackRemainsBoundedAndLearnsADeepEndpoint(t *testing.T) {
	var badSecond atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/good" {
			if r.URL.Query().Get("name") == "second.example" {
				badSecond.Add(1)
			}
			<-r.Context().Done()
			return
		}
		fmt.Fprint(w, `{"Status":0,"Answer":[{"type":1,"TTL":60,"data":"142.250.1.1"}]}`)
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	var endpoints []DoHEndpoint
	for i := 0; i < 8; i++ {
		endpoints = append(endpoints, DoHEndpoint{URL: fmt.Sprintf("https://example.com/bad%d", i)})
	}
	endpoints = append(endpoints, DoHEndpoint{URL: "https://example.com/good"})
	r := NewDoH(endpoints, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}, pool)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	began := time.Now()
	if _, err := r(ctx, "first.example"); err != nil {
		t.Fatal(err)
	}
	if time.Since(began) > time.Second {
		t.Fatal("deep resolver fallback accumulated serial delays")
	}
	if _, err := r(ctx, "second.example"); err != nil {
		t.Fatal(err)
	}
	if badSecond.Load() != 0 {
		t.Fatal("working deep endpoint was not tried first for the next name")
	}
}

func TestDoHResolvesCachesAndVerifiesCertificates(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Query().Get("name") != "youtube.com" || r.URL.Query().Get("type") != "A" {
			http.Error(w, "bad query", 400)
			return
		}
		w.Write([]byte(`{"Status":0,"Answer":[{"type":5,"TTL":60,"data":"alias.example."},{"type":1,"TTL":120,"data":"142.250.1.1"}]}`))
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	// httptest certificates are valid for 127.0.0.1 / example.com.
	r := NewDoH([]DoHEndpoint{{URL: "https://example.com/resolve"}}, dial, pool)
	for i := 0; i < 2; i++ {
		ips, err := r(context.Background(), "youtube.com")
		if err != nil || len(ips) != 1 || ips[0] != "142.250.1.1" {
			t.Fatalf("ips=%v err=%v", ips, err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("answer not cached: %d requests", hits.Load())
	}
	if ips, _ := r(context.Background(), "10.1.2.3"); len(ips) != 1 || ips[0] != "10.1.2.3" {
		t.Fatalf("IP literal changed: %v", ips)
	}
	// Without the test CA the certificate must be rejected.
	untrusted := NewDoH([]DoHEndpoint{{URL: "https://example.com/resolve"}}, dial, nil)
	if _, err := untrusted(context.Background(), "youtube.com"); err == nil {
		t.Fatal("certificate verification was skipped")
	}
	// Android Balanced/Fast supply no external exit dialer. This path used
	// to dereference nil when its first real hostname needed encrypted DNS.
	withDefaultDialer := NewDoH([]DoHEndpoint{{URL: "https://example.com/resolve", Addr: srv.Listener.Addr().String()}}, nil, pool)
	if ips, err := withDefaultDialer(context.Background(), "youtube.com"); err != nil || len(ips) != 1 {
		t.Fatalf("default DoH dialer failed: %v, %v", ips, err)
	}
}

func TestDoHAAAAReturnsIPv6Records(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") != "AAAA" {
			http.Error(w, "want AAAA", 400)
			return
		}
		w.Write([]byte(`{"Status":0,"Answer":[{"type":28,"TTL":60,"data":"2a00:1450:4001:81b::200e"}]}`))
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	r := NewDoHType([]DoHEndpoint{{URL: "https://example.com/resolve"}}, dial, pool, "AAAA")
	ips, err := r(context.Background(), "youtube.com")
	if err != nil || len(ips) != 1 || ips[0] != "2a00:1450:4001:81b::200e" {
		t.Fatalf("ips=%v err=%v", ips, err)
	}
}

func TestDesyncFamiliesIncludeIPv6Twins(t *testing.T) {
	v6 := 0
	for _, u := range DesyncUpstreams() {
		if u.Network == "tcp6" {
			v6++
		}
	}
	if v6 != 2 {
		t.Fatalf("expected 2 IPv6 families, got %d", v6)
	}
}

func TestDoHDecoySNIIsSentButTheCertificateIsStillVerified(t *testing.T) {
	var seen atomic.Value
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Status":0,"Answer":[{"type":1,"TTL":60,"data":"142.250.1.1"}]}`))
	}))
	srv.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		seen.Store(h.ServerName)
		return nil, nil
	}}
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	ep := DoHEndpoint{URL: "https://example.com/resolve", ServerName: "example.com", FrontSNI: "decoy.test"}
	ips, err := NewDoH([]DoHEndpoint{ep}, dial, pool)(context.Background(), "youtube.com")
	if err != nil || len(ips) != 1 {
		t.Fatalf("ips=%v err=%v", ips, err)
	}
	if got, _ := seen.Load().(string); got != "decoy.test" {
		t.Fatalf("the wire carried SNI %q", got)
	}
	// A certificate that is not valid for the real service name is refused even
	// though the decoy name was what the handshake asked for.
	bad := ep
	bad.ServerName = "other.example"
	if _, err := NewDoH([]DoHEndpoint{bad}, dial, pool)(context.Background(), "youtube.com"); err == nil {
		t.Fatal("certificate for another name accepted")
	}
}

func TestDoHCanUseTheEndpointsOwnTLSDialer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Status":0,"Answer":[{"type":1,"TTL":60,"data":"142.250.1.1"}]}`))
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	var dialed atomic.Int32
	ep := DoHEndpoint{URL: "https://example.com/resolve", DialTLS: func(ctx context.Context) (net.Conn, error) {
		dialed.Add(1)
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		c := tls.Client(raw, &tls.Config{ServerName: "example.com", RootCAs: pool, NextProtos: []string{"http/1.1"}})
		return c, c.HandshakeContext(ctx)
	}}
	ips, err := NewDoH([]DoHEndpoint{ep}, nil, nil)(context.Background(), "youtube.com")
	if err != nil || len(ips) != 1 || ips[0] != "142.250.1.1" {
		t.Fatalf("ips=%v err=%v", ips, err)
	}
	if dialed.Load() != 1 {
		t.Fatalf("own dialer used %d times", dialed.Load())
	}
}
