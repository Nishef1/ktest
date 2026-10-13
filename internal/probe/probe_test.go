package probe

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func trusted(t *testing.T, server *httptest.Server) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	return pool
}

func TestHTTPAndHostOverride(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "front.example" {
			t.Errorf("Host=%q", r.Host)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("X", 8192)))
	}))
	defer server.Close()
	result, err := Run(context.Background(), Config{URL: server.URL, Host: "front.example", MaxBodyBytes: 128})
	if err != nil || !result.Success || result.BodyBytes != 128 || result.Phase != "complete" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestTLSCertificateValidation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer server.Close()
	untrusted, err := Run(context.Background(), Config{URL: server.URL, Timeout: 3 * time.Second})
	if err != nil || untrusted.Reachable || untrusted.Phase != "tls" {
		t.Fatalf("untrusted=%+v err=%v", untrusted, err)
	}
	trusted, err := Run(context.Background(), Config{URL: server.URL, RootCAs: trusted(t, server)})
	if err != nil || !trusted.Success || trusted.Phase != "complete" || trusted.TLSMS < 0 {
		t.Fatalf("trusted=%+v err=%v", trusted, err)
	}
}

func TestHTTPRedirectIsNotFollowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Fatalf("unexpected redirect follow: %s", r.URL.Path)
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer server.Close()
	result, err := Run(context.Background(), Config{URL: server.URL})
	if err != nil || !result.Reachable || result.Success || result.Status != 302 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestInvalidInput(t *testing.T) {
	cases := []Config{
		{URL: "file:///etc/passwd"},
		{URL: "https://example.com", Network: "udp"},
		{URL: "https://example.com", ConnectAddr: "not-port"},
		{URL: "https://example.com", Host: "bad\nHost"},
		{URL: "https://example.com", Timeout: -time.Second},
	}
	for _, tc := range cases {
		if _, err := Run(context.Background(), tc); err == nil {
			t.Fatalf("input %+v should fail", tc)
		}
	}
}

func TestHTTPRejectedIsNotSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusMisdirectedRequest) }))
	defer server.Close()
	result, err := Run(context.Background(), Config{URL: server.URL})
	if err != nil || !result.Reachable || result.Success || result.Status != 421 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestValidTLSVersionReported(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	result, err := Run(context.Background(), Config{URL: server.URL, RootCAs: trusted(t, server)})
	if err != nil || !result.Success || result.TLSVersion == "" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestProofFreshnessAndRedirect(t *testing.T) {
	seen := map[string]bool{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challenge := r.Header.Get("X-Ktest-Challenge")
		if len(challenge) != 32 || seen[challenge] {
			t.Errorf("missing or repeated challenge: %q", challenge)
		}
		seen[challenge] = true
		if r.Header.Get("Cache-Control") != "no-store" {
			t.Error("cache control missing")
		}
		w.Header().Set("X-Ktest-Proof", challenge)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	for i := 0; i < 2; i++ {
		r, err := Run(context.Background(), Config{URL: server.URL, RootCAs: trusted(t, server), Proof: true})
		if err != nil || !r.Success || r.ProofStatus != "verified" {
			t.Fatalf("res=%+v err=%v", r, err)
		}
	}
	if len(seen) != 2 {
		t.Fatal("challenge was reused")
	}
}

func TestProofRejectsFalsePositive(t *testing.T) {
	for _, response := range []string{"", "replayed-old-proof"} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if response != "" {
				w.Header().Set("X-Ktest-Proof", response)
			}
			_, _ = io.WriteString(w, "OK")
		}))
		r, err := Run(context.Background(), Config{URL: server.URL, RootCAs: trusted(t, server), Proof: true})
		server.Close()
		if err != nil || !r.Reachable || r.Success || r.ProofStatus == "verified" {
			t.Fatalf("res=%+v err=%v", r, err)
		}
	}
}

func TestProofRequiresTLSForRemote(t *testing.T) {
	if _, err := Run(context.Background(), Config{URL: "http://example.org", Proof: true}); err == nil {
		t.Fatal("remote plaintext proof should be rejected")
	}
}
