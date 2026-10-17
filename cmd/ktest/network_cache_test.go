package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNetworkMeasurementsAreIsolatedAndExpireWithoutAuthorizingExits(t *testing.T) {
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	p1 := aetherProfile{Label: "fast but less reliable", Args: []string{"--masque", "--h3"}}
	p2 := aetherProfile{Label: "stable", Args: []string{"--masque", "--h2"}}
	fast := measurementFor(p1)
	fast.State, fast.Attempts, fast.Successes, fast.LatencyMS = "verified", 4, 3, 50
	fast.ExitIP, fast.Country = "1.1.1.1", "US"
	stable := measurementFor(p2)
	stable.State, stable.Attempts, stable.Successes, stable.LatencyMS = "verified", 4, 4, 300
	stable.ExitIP, stable.Country = "8.8.8.8", "DE"
	if err := saveMeasurement("network-a", "core-a", fast); err != nil {
		t.Fatal(err)
	}
	if err := saveMeasurement("network-a", "core-a", stable); err != nil {
		t.Fatal(err)
	}
	history, err := cachedNetwork("network-a", "core-a")
	if err != nil {
		t.Fatal(err)
	}
	profiles := []aetherProfile{p1, p2}
	if measuredProfilesFirst(profiles, history, ModeFast)[0].id() != p1.id() {
		t.Fatal("Fast ignored lower measured latency")
	}
	if measuredProfilesFirst(profiles, history, ModeBalanced)[0].id() != p2.id() {
		t.Fatal("Balanced ignored reliability")
	}
	for _, key := range []struct{ network, core string }{{"network-b", "core-a"}, {"network-a", "core-b"}} {
		p, err := cachedNetwork(key.network, key.core)
		if err != nil || len(p.Results) != 0 {
			t.Fatal("reused another network/core", p, err)
		}
	}
	fast.Checked = time.Now().Add(-25 * time.Hour)
	history.Results[p1.id()] = fast
	if measuredProfilesFirst(profiles, history, ModeFast)[0].id() != p2.id() {
		t.Fatal("expired measurement won")
	}
	stable.State = "timeout"
	stable.Checked = time.Now()
	history.Results[p2.id()] = stable
	if measuredProfilesFirst(profiles, history, ModeBalanced)[0].id() != p1.id() {
		t.Fatal("recent timeout did not yield to an untested/stale alternative")
	}
	// Cached data is deliberately not a smartproxy.Upstream or a verification lease.
	var out bytes.Buffer
	printNetworkRecommendations(plainTerm(&out), "network-a", "core-a", profiles)
	if !strings.Contains(strings.Join(strings.Fields(out.String()), " "), "live exit verification is required") {
		t.Fatal("cached recommendation advertised as live", out.String())
	}
}

func TestNetworkCachePreservesCorruptFilesAndConcurrentMeasurements(t *testing.T) {
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	var wg sync.WaitGroup
	for _, name := range []string{"one", "two", "three"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := aetherProfile{Label: name}
			if err := saveMeasurement("network", "core", measurementFor(p)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	p, err := cachedNetwork("network", "core")
	if err != nil || len(p.Results) != 3 {
		t.Fatal("concurrent results lost", p, err)
	}
	bad := []byte("{broken cache")
	if err := os.WriteFile(networkCacheFile(), bad, 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveMeasurement("network", "core", measurementFor(aetherProfile{Label: "new"})); err == nil {
		t.Fatal("corrupt cache silently replaced")
	}
	got, _ := os.ReadFile(networkCacheFile())
	if !bytes.Equal(got, bad) {
		t.Fatal("corrupt cache changed")
	}
}

func TestCarrierMeasurementsNeverBecomeForeignAIRecommendations(t *testing.T) {
	p := aetherProfile{Label: "local-country WARP", Args: []string{"--masque", "--h2"}}
	r := measurementFor(p)
	r.State, r.Attempts, r.Successes, r.LatencyMS = "carrier", 6, 5, 100
	r.ExitIP, r.Country = "1.1.1.1", "IR"
	for _, mode := range []ConnectionMode{ModeFast, ModeBalanced, ModeWindscribeAether} {
		if measurementScore(r, mode) >= 1e12 {
			t.Errorf("%s rejected a usable carrier", mode)
		}
	}
	for _, mode := range []ConnectionMode{ModeAether, ModePsiphon, ModeTor} {
		if measurementScore(r, mode) < 1e12 {
			t.Errorf("%s accepted IR as a foreign exit", mode)
		}
	}
	r.State = "verified" // Even a mislabeled cache entry cannot upgrade eligibility.
	if measurementScore(r, ModeAether) < 1e12 {
		t.Fatal("cached label bypassed location policy")
	}
}

func TestProfileStateStaysWithTransportAfterReorderingAndECHRefresh(t *testing.T) {
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	p := aetherProfile{Label: "h2", Args: []string{"--masque", "--h2", "--ech", "old", "--enroll-address", "1.2.3.4"}}
	q := aetherProfile{Label: p.Label, Args: []string{"--masque", "--h2", "--ech", "new", "--enroll-address", "2.3.4.5"}}
	if p.id() != q.id() {
		t.Fatal("ECH refresh invalidated stable profile identity")
	}
	first := enrollmentArg(aetherRunArgs(0, p, 10830), "--config")
	second := enrollmentArg(aetherRunArgs(4, q, 10834), "--config")
	if first != second || filepath.Dir(first) != warpDir() {
		t.Fatal("sorting mixed profile state", first, second)
	}
	q.Args = []string{"--masque", "--h3"}
	if q.id() == p.id() {
		t.Fatal("different transports share state")
	}
	t.Setenv("KTEST_NETWORK_ID", "wifi-a")
	a := networkSignature(context.Background())
	t.Setenv("KTEST_NETWORK_ID", "wifi-b")
	if a == networkSignature(context.Background()) || strings.Contains(a, "wifi") {
		t.Fatal("network identity was not isolated/hashed")
	}
}
