package smartproxy

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

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
}
