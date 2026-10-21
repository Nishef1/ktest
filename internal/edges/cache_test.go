package edges

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/probe"
)

func verifiedResult(ip string, ms int64) ScanResult {
	return ResultOf(ip, probe.Result{Success: true, TLSVersion: "TLS 1.3", Status: 204, ElapsedMS: ms})
}

func TestVerifiedEdgesArePerProviderAndNetwork(t *testing.T) {
	dir := t.TempDir()
	failed := ResultOf("104.16.0.9", probe.Result{Error: "i/o timeout"})
	if failed.HTTPVerified || failed.Error != "timeout" {
		t.Fatalf("failed probe recorded as %+v", failed)
	}
	results := []ScanResult{verifiedResult("104.16.0.2", 80), failed, verifiedResult("104.16.0.1", 30)}
	if err := SaveVerified(dir, VerifiedCache{Provider: "cloudflare", Network: "ab12", Source: "test", Results: results}); err != nil {
		t.Fatal(err)
	}
	if got := LoadVerified(dir, "cloudflare", "ab12"); !reflect.DeepEqual(got, []string{"104.16.0.1", "104.16.0.2"}) {
		t.Fatalf("got %v, want verified edges fastest first", got)
	}
	for _, c := range []struct{ provider, network string }{{"cloudflare", "cd34"}, {"cloudflare", ""}, {"akamai", "ab12"}} {
		if got := LoadVerified(dir, c.provider, c.network); got != nil {
			t.Fatalf("%s/%q leaked %v", c.provider, c.network, got)
		}
	}
	// Android's network-independent cache keeps its file name.
	if err := SaveVerified(dir, VerifiedCache{Provider: "fastly", Source: "test", Results: results}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "verified-fastly.json")); err != nil || len(LoadVerified(dir, "fastly", "")) != 2 {
		t.Fatalf("network-independent cache not usable: %v", err)
	}
}

func TestVerifiedEdgesRefuseBadInput(t *testing.T) {
	dir := t.TempDir()
	ok := []ScanResult{verifiedResult("104.16.0.1", 10)}
	for name, c := range map[string]VerifiedCache{
		"unknown provider": {Provider: "nope", Source: "s", Results: ok},
		"path in network":  {Provider: "cloudflare", Network: "../x", Source: "s", Results: ok},
		"no source":        {Provider: "cloudflare", Source: "", Results: ok},
		"nothing verified": {Provider: "cloudflare", Source: "s", Results: []ScanResult{{IP: "104.16.0.1"}}},
	} {
		if SaveVerified(dir, c) == nil {
			t.Errorf("%s: saved", name)
		}
	}
	stale := VerifiedCache{Provider: "cloudflare", Network: "aa", Source: "s", VerifiedAt: time.Now().Add(-VerifiedTTL - time.Minute), Results: ok}
	if err := SaveVerified(dir, stale); err != nil {
		t.Fatal(err)
	}
	if got := LoadVerified(dir, "cloudflare", "aa"); got != nil {
		t.Fatalf("stale cache used: %v", got)
	}
	private := VerifiedCache{Provider: "cloudflare", Network: "bb", Source: "s", Results: []ScanResult{verifiedResult("10.0.0.1", 5)}}
	if err := SaveVerified(dir, private); err != nil {
		t.Fatal(err)
	}
	if got := LoadVerified(dir, "cloudflare", "bb"); got != nil {
		t.Fatalf("private address used: %v", got)
	}
}

func TestVerifiedEdgesCappedAndPruned(t *testing.T) {
	dir := t.TempDir()
	var many []ScanResult
	for i := range 150 {
		many = append(many, verifiedResult(fmt.Sprintf("104.16.%d.%d", i/200, i%200+1), int64(150-i)))
	}
	old := filepath.Join(dir, "verified-google-ffff.json")
	if err := os.WriteFile(old, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-VerifiedTTL - time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	if err := SaveVerified(dir, VerifiedCache{Provider: "cloudflare", Network: "ab", Source: "s", Results: many}); err != nil {
		t.Fatal(err)
	}
	got := LoadVerified(dir, "cloudflare", "ab")
	if len(got) != maxVerified || got[0] != "104.16.0.150" {
		t.Fatalf("got %d edges starting %v, want the %d fastest", len(got), got[:1], maxVerified)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("expired cache of another network not pruned")
	}
}
