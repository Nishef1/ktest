package proofserver

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Nishef1/ktest/internal/probe"
)

func TestProofServerRoundTrip(t *testing.T) {
	server := httptest.NewTLSServer(Handler())
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	result, err := probe.Run(context.Background(), probe.Config{URL: server.URL + "/__ktest/proof", Proof: true, RootCAs: pool})
	if err != nil || !result.Success || result.ProofStatus != "verified" || result.Status != 204 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestProofRejectsMalformedChallenge(t *testing.T) {
	server := httptest.NewServer(Handler())
	defer server.Close()
	for _, token := range []string{"", "../../../../secret", "xyz"} {
		req, err := http.NewRequest("GET", server.URL+"/__ktest/proof", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Ktest-Challenge", token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 || resp.Header.Get("X-Ktest-Proof") != "" {
			t.Fatalf("invalid challenge accepted, status=%d", resp.StatusCode)
		}
	}
}
