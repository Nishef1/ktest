package experiment

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/probe"
)

func TestVariants(t *testing.T) {
	base := probe.Config{URL: "https://example.test/", ConnectAddr: "127.0.0.1:443", Host: "front.test", ServerName: "front.test"}
	variants, err := Variants(base)
	if err != nil || len(variants) != 5 {
		t.Fatalf("variants=%v err=%v", variants, err)
	}
	if variants[0].Config.ConnectAddr != "" || variants[1].Config.ConnectAddr == "" {
		t.Fatal("baseline must be unpinned; variant 2 pinned")
	}
	if variants[2].Config.Host != "front.test" || variants[2].Config.ServerName != "" {
		t.Fatal("host-only comparison changed SNI")
	}
	if variants[3].Config.Host != "" || variants[3].Config.ServerName != "front.test" {
		t.Fatal("sni-only comparison changed host")
	}
	if variants[4].Config.Host != "front.test" || variants[4].Config.ServerName != "front.test" {
		t.Fatal("combined is incomplete")
	}
}

func TestPairingOrderAndSummary(t *testing.T) {
	p := Plan{Base: probe.Config{URL: "https://example.test", Host: "front.test"}, Rounds: 3}
	calls := []string{}
	run := func(_ context.Context, cfg probe.Config) (probe.Result, error) {
		v := "baseline"
		if cfg.Host != "" {
			v = "host"
		}
		calls = append(calls, v)
		if v == "host" {
			return probe.Result{Phase: "complete", Reachable: true, Success: true, ElapsedMS: 11}, nil
		}
		return probe.Result{Phase: "tls", Error: "test failure", ElapsedMS: 27}, nil
	}
	r, err := Run(context.Background(), p, run)
	if err != nil || len(r.Samples) != 6 || len(r.Summary) != 2 {
		t.Fatalf("report=%+v err=%v", r, err)
	}
	want := []string{"baseline", "host", "host", "baseline", "baseline", "host"}
	for i, v := range want {
		if calls[i] != v {
			t.Fatalf("calls=%v", calls)
		}
	}
	if r.Summary[0].Outcomes["tls_error"] != 3 || r.Summary[0].MedianElapsedMS != 27 {
		t.Fatal(r.Summary[0])
	}
	if r.Summary[1].SuccessfulHTTP != 3 || r.Summary[1].MedianElapsedMS != 11 {
		t.Fatal(r.Summary[1])
	}
}

func TestControlledTLSWithPinnedRoute(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	// The test makes no attempt to circumvent certificate verification.
	// The resolver-free connection uses the server's real TLS identity.
	r, err := Run(context.Background(), Plan{Base: probe.Config{URL: srv.URL, ConnectAddr: srv.Listener.Addr().String(), RootCAs: pool, Timeout: 2 * time.Second}, Rounds: 2}, nil)
	if err != nil || len(r.Summary) != 2 || r.Summary[0].SuccessfulHTTP != 2 || r.Summary[1].SuccessfulHTTP != 2 {
		t.Fatalf("report=%+v err=%v", r, err)
	}
}

func TestValidation(t *testing.T) {
	if _, err := Run(context.Background(), Plan{Base: probe.Config{URL: "https://example.org", Host: "x"}, Rounds: 0}, nil); err == nil {
		t.Fatal("expected bounds error")
	}
	if _, err := Variants(probe.Config{URL: "https://example.org"}); err == nil {
		t.Fatal("empty comparisons")
	}
}
