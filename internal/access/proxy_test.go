package access

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAccessProxyForwardsTLSUnmodified(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "from the intended server")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	proxy, err := NewProxy([]string{"localhost"}, u.Host)
	if err != nil {
		t.Fatal(err)
	}
	ps := httptest.NewServer(proxy)
	defer ps.Close()
	pu, _ := url.Parse(ps.URL)
	trust := x509.NewCertPool()
	trust.AddCert(upstream.Certificate())
	// httptest's certificate is valid for example.com, and never installed globally.
	tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: trust, ServerName: "example.com"}}
	client := &http.Client{Transport: tr, Timeout: 4 * time.Second}
	res, err := client.Get("https://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil || !strings.Contains(string(b), "from the intended server") {
		t.Fatalf("body=%q err=%v", b, err)
	}
	if res.TLS == nil || len(res.TLS.PeerCertificates) == 0 {
		t.Fatal("TLS not preserved")
	}
}

func TestNoOpenProxy(t *testing.T) {
	p, err := NewProxy([]string{"example.org"}, "127.0.0.1:40443")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(p)
	defer server.Close()
	for _, target := range []string{"other.org:443", "example.org:80", "example.org:444"} {
		req, err := http.NewRequest(http.MethodConnect, server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = target
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("target %s returned %v", target, response.Status)
		}
	}
	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("HTTP URL should be denied: %d", resp.StatusCode)
	}
}

func TestValidateLoopbackOnly(t *testing.T) {
	if _, err := NewProxy([]string{"example.org"}, "0.0.0.0:5555"); err == nil {
		t.Fatal("bridge must be loopback")
	}
	if _, err := NewProxy([]string{"*"}, "127.0.0.1:5555"); err == nil {
		t.Fatal("wildcard should be rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Listen(ctx, "0.0.0.0:0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})); err == nil {
		t.Fatal("nonlocal bind accepted")
	}
}
