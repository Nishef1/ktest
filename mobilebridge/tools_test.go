package mobilebridge

import "testing"

func TestToolsRejectInvalidInputBeforeNetworkWork(t *testing.T) {
	for _, tc := range []struct {
		provider     string
		budget, goal int
	}{
		{"unknown", 30, 10}, {"cloudflare", -1, 10}, {"cloudflare", 30, -1}, {"cloudflare", 1, 10},
	} {
		if err := StartCDNScanForProvider(tc.provider, tc.budget, tc.goal); err == nil {
			t.Fatalf("invalid scan accepted: %+v", tc)
		}
	}
	if _, err := DiagnoseNetwork("https://example.com", "udp"); err == nil {
		t.Fatal("invalid diagnosis network accepted")
	}
	if _, err := TestFronts("https://example.com", "example.com", "example.com", "invalid", 1, false); err == nil {
		t.Fatal("invalid multi-edge plan accepted")
	}
}
