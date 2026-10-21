package main

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/Nishef1/ktest/internal/edges"
	"github.com/Nishef1/ktest/internal/probe"
)

func saveTestEdges(t *testing.T, network, provider string, ips ...string) {
	t.Helper()
	var results []edges.ScanResult
	for i, ip := range ips {
		results = append(results, edges.ResultOf(ip, probe.Result{Success: true, TLSVersion: "TLS 1.3", Status: 200, ElapsedMS: int64(10 + i)}))
	}
	if err := saveCDNScan(network, provider, "test", results); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopUsesEdgesVerifiedOnThisNetwork(t *testing.T) {
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	t.Setenv("KTEST_NETWORK_ID", "home")
	home := networkSignature(context.Background())
	saveTestEdges(t, home, "cloudflare", "104.16.0.1", "104.16.0.2")
	saveTestEdges(t, home, "akamai", "23.0.0.1")
	saveTestEdges(t, home, "google", "142.250.0.1")

	if got := frontPreferredEdges(context.Background()); !reflect.DeepEqual(got, map[string][]string{
		"cloudflare": {"104.16.0.1", "104.16.0.2"}, "google": {"142.250.0.1"}}) {
		t.Fatalf("fronting edges = %v", got)
	}
	samples := []string{"104.16.0.2", "151.101.0.1"}
	if got := withSavedPsiphonEdges(home, samples); !slices.Equal(got, []string{"23.0.0.1", "104.16.0.1", "104.16.0.2", "151.101.0.1"}) {
		t.Fatalf("psiphon edges = %v, want saved per provider then samples", got)
	}
	if got := withSavedCloudflareEdges(home, []string{"104.16.0.9", "104.16.0.1"}); !slices.Equal(got, []string{"104.16.0.1", "104.16.0.2", "104.16.0.9"}) {
		t.Fatalf("windscribe candidates = %v", got)
	}

	// Another network, or none identified, reuses nothing.
	t.Setenv("KTEST_NETWORK_ID", "cafe")
	if got := frontPreferredEdges(context.Background()); len(got) != 0 {
		t.Fatalf("edges leaked to another network: %v", got)
	}
	if got := withSavedPsiphonEdges("", samples); !slices.Equal(got, samples) {
		t.Fatalf("unidentified network = %v, want samples only", got)
	}
	if saveCDNScan("", "cloudflare", "test", nil) == nil {
		t.Fatal("saved without a network identity")
	}
}

func TestSavedPsiphonEdgesLeaveRoomForSamples(t *testing.T) {
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	t.Setenv("KTEST_NETWORK_ID", "home")
	home := networkSignature(context.Background())
	var cf []string
	for i := range 50 {
		cf = append(cf, fmt.Sprintf("104.16.1.%d", i+1))
	}
	saveTestEdges(t, home, "cloudflare", cf...)
	var samples []string
	for i := range 40 {
		samples = append(samples, fmt.Sprintf("151.101.1.%d", i+1))
	}
	got := withSavedPsiphonEdges(home, samples)
	if len(got) != maxPsiphonEdges || got[0] != cf[0] || got[maxSavedPsiphonEdges] != samples[0] {
		t.Fatalf("got %d edges %v", len(got), got)
	}
}
