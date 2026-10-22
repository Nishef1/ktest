package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/front"
)

func TestFrontingPresetUsesRealFamilyStrategies(t *testing.T) {
	for _, tc := range []struct {
		url, family, sni string
		ech              bool
	}{
		{"https://api.x.com/2/users/me", "cloudflare", front.CloudflareECH, true},
		{"https://api.twitter.com/1.1/help/configuration.json", "cloudflare", front.CloudflareECH, true},
		{"https://www.youtube.com/generate_204", "google", "www.google.com", false},
		{"https://www.instagram.com/", "meta", "www.microsoft.com", false},
		{"https://pbs.twimg.com/media/test.jpg", "twimg", "pypi.org", false},
	} {
		raw, err := FrontingPreset(tc.url)
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			URL, SNI, HTTPHost, Family, Note string
			UsesECH                          bool `json:"uses_ech"`
			Supported                        bool
		}
		if err = json.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatal(err)
		}
		if !got.Supported || got.Family != tc.family || got.SNI != tc.sni || got.UsesECH != tc.ech || got.Note == "" {
			t.Fatalf("incorrect family strategy: %s", raw)
		}
	}
	for _, rawURL := range []string{"https://outside.example/test", "https://www.youtube.com:8443/"} {
		raw, err := FrontingPreset(rawURL)
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Supported bool
			Note      string
		}
		_ = json.Unmarshal([]byte(raw), &got)
		if got.Supported || got.Note == "" {
			t.Fatalf("unsupported fronting claimed: %s", raw)
		}
	}
}

func TestTargetFrontingValidatesBeforeNetworkAndRejectsActiveWork(t *testing.T) {
	dir := t.TempDir()
	for _, ips := range []string{"", "edge.example", "127.0.0.1", "10.0.0.1", "100.64.0.1", "192.0.2.1", "198.18.0.1", "2001:db8::1", "::1", "8.8.8.8:443", "8.8.8.8,8.8.8.8", strings.Repeat("8.8.8.8,", 13)} {
		if _, err := TestTargetFronting(dir, "https://youtube.com/", ips, 1); err == nil {
			t.Errorf("accepted invalid comparison edges %q", ips)
		}
	}
	for _, rounds := range []int{0, 4} {
		if _, err := TestTargetFronting(dir, "https://youtube.com/", "8.8.8.8", rounds); err == nil {
			t.Errorf("accepted rounds %d", rounds)
		}
	}
	raw, err := TestTargetFronting(dir, "https://outside.example/path", "8.8.8.8", 1)
	var unsupported struct {
		Supported  bool              `json:"supported"`
		Candidates []json.RawMessage `json:"candidates"`
		Note       string            `json:"note"`
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(raw), &unsupported); err != nil {
		t.Fatal(err)
	}
	if unsupported.Supported || len(unsupported.Candidates) != 0 || unsupported.Note == "" {
		t.Fatalf("unknown family not clearly unsupported: %s %v", raw, err)
	}
	proxyMu.Lock()
	previous := pendingProxy
	pendingProxy = &proxyStartup{phase: "calibrating"}
	proxyMu.Unlock()
	t.Cleanup(func() { proxyMu.Lock(); pendingProxy = previous; proxyMu.Unlock() })
	if _, err := TestTargetFronting(dir, "https://youtube.com/", "8.8.8.8", 1); err == nil {
		t.Fatal("target probe raced startup/calibration")
	}
}

func TestTargetFrontingAggregationNeverPromotesTCPOrServiceRefusal(t *testing.T) {
	// The protocol itself is exercised by front's local TLS fixtures. This
	// deterministic runner tests Tools' evidence aggregation at its boundary.
	for _, tc := range []struct {
		name       string
		result     front.ProbeResult
		assessment string
		http2xx    int
	}{
		{"tcp", front.ProbeResult{TCPConnected: true, Err: errors.New("untrusted cert")}, "tcp_only", 0},
		{"refusal", front.ProbeResult{TCPConnected: true, TLSVerified: true, Status: 403, BodyBytes: 5, BodyComplete: true}, "service_refused", 0},
		{"body", front.ProbeResult{TCPConnected: true, TLSVerified: true, Status: 200, BodyBytes: 5, BodyComplete: true}, "http_2xx_unverified", 2},
		{"truncated", front.ProbeResult{TCPConnected: true, TLSVerified: true, Status: 200, BodyBytes: 5, Err: errors.New("unexpected EOF")}, "body_incomplete", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			runner := func(ctx context.Context, host, path, ip string) []front.ProbeResult {
				calls++
				if host != "api.x.com" || path != "/2/users/me?x=one" || ip != "8.8.8.8" {
					t.Fatalf("target changed: %s %s %s", host, path, ip)
				}
				r := tc.result
				r.Site = host
				r.Family = "cloudflare"
				r.Front = front.Front{ECH: front.CloudflareECH}
				r.Took = time.Duration(calls) * time.Millisecond
				return []front.ProbeResult{r}
			}
			report := runTargetFronting(context.Background(), "https://api.x.com/2/users/me?x=one", []string{"8.8.8.8"}, 2, runner)
			if calls != 2 || len(report.Candidates) != 1 {
				t.Fatalf("comparison lost attempts: %+v", report)
			}
			got := report.Candidates[0]
			if got.Assessment != tc.assessment || got.OriginVerified != 0 || got.HTTP2xx != tc.http2xx || got.Attempts != 2 || got.SNI != front.CloudflareECH || !got.ECH || got.Method != front.MethodName("cloudflare", front.Front{ECH: front.CloudflareECH}) || got.HTTPHost != "api.x.com" {
				t.Fatalf("false evidence/metadata: %+v", got)
			}
		})
	}
}
