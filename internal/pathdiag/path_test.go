package pathdiag

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIndependentDNSAndTCP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("path must not make HTTP request") }))
	defer server.Close()
	result, err := Run(context.Background(), Config{URL: server.URL, Network: "tcp4"})
	if err != nil || result.DNSStatus != "ok" || result.TCPStatus != "ok" || result.TLSStatus != "not_applicable" || result.Outcome != "tcp_connected_no_http_test" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestPinnedConnectSurvivesDNSFailureAndVerifiesTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("path must not make HTTP request") }))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	result, err := Run(context.Background(), Config{
		URL: "https://definitely-does-not-exist.invalid/", ConnectAddr: server.Listener.Addr().String(),
		SNI: "127.0.0.1", RootCAs: pool, Timeout: 3 * time.Second,
	})
	if err != nil || result.DNSStatus != "failed" || result.TCPStatus != "ok" || result.TLSStatus != "verified" || result.Outcome != "tls_verified_no_http_test" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestTLSInvalidCertificateIsNotReportedAsVerified(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	result, err := Run(context.Background(), Config{URL: server.URL})
	if err != nil || result.TCPStatus != "ok" || result.TLSStatus != "failed" || result.Outcome != "tls_unavailable" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestTCPFailureDifferentFromTLSFailure(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	result, err := Run(context.Background(), Config{URL: "https://localhost", ConnectAddr: address, Network: "tcp4"})
	if err != nil || result.TCPStatus != "failed" || result.TLSStatus != "skipped" || result.Outcome != "tcp_unavailable" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestValidation(t *testing.T) {
	cases := []Config{
		{URL: "file:///etc/passwd"}, {URL: "https://example.org", Network: "udp"},
		{URL: "https://example.org", ConnectAddr: "no-port"},
		{URL: "https://example.org", Timeout: 40 * time.Second},
		{URL: "http://example.org", SNI: "front.example"},
		{URL: "https://example.org", SNI: "bad\nname"},
	}
	for _, cfg := range cases {
		if _, err := Run(context.Background(), cfg); err == nil {
			t.Errorf("expected failure for %+v", cfg)
		}
	}
}
