package mobilebridge

import "testing"

func TestToolsRejectInvalidInputBeforeNetworkWork(t *testing.T) {
	for _, tc := range []struct {
		provider     string
		budget, goal int
	}{
		{"unknown", 30, 10}, {"cloudflare", 301, 10}, {"cloudflare", 30, 0}, {"cloudflare", 1, 10},
	} {
		if err := StartCDNScanForProvider(tc.provider, tc.budget, tc.goal); err == nil {
			t.Fatalf("invalid scan accepted: %+v", tc)
		}
	}
	for _, address := range []string{"example.com:443", "192.0.2.1:0", "192.0.2.1:70000"} {
		if _, err := TestWindscribeCarrier(address, "example.com", "example.com", "wstunnel"); err == nil {
			t.Fatalf("invalid entry accepted: %s", address)
		}
	}
	for _, name := range []string{"example.com\r\nInjected: value", "https://example.com", "bad..example", "-bad.example", "127.0.0.1"} {
		if _, err := TestWindscribeCarrier("192.0.2.1:443", name, name, "stealth"); err == nil {
			t.Fatalf("invalid TLS/HTTP name accepted: %q", name)
		}
	}
	if _, err := DiagnoseNetwork("https://example.com", "udp"); err == nil {
		t.Fatal("invalid diagnosis network accepted")
	}
	if _, err := TestFronts("https://example.com", "example.com", "example.com", "invalid", 1, false); err == nil {
		t.Fatal("invalid multi-edge plan accepted")
	}
}
