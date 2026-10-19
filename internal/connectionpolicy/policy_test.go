package connectionpolicy

import (
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

func TestModeCatalogIsUniqueAndFaithfulToCLI(t *testing.T) {
	expected := []string{"balanced", "fast", "aether", "tor", "windscribe", "psiphon", "windscribe-aether"}
	modes := AndroidModes()
	if len(modes) != len(expected) {
		t.Fatalf("expected %d modes, got %d", len(expected), len(modes))
	}
	for i, m := range modes {
		if m.ID != expected[i] || m.Title == "" || m.Subtitle == "" {
			t.Fatalf("mode %d mismatches CLI: %+v", i, m)
		}
		if m.Available && m.Limitation == "" {
			t.Fatalf("partial Android port missing caveat: %q", m.ID)
		}
	}
	if Title("tor") != "Aether to Tor" || Title("psiphon") != "Aether to Psiphon" {
		t.Fatal("Android silently renamed a desktop CLI policy")
	}
}

func TestConfigureMatchesCLIForAllModes(t *testing.T) {
	protected := func(h string) bool { return h == "chatgpt.com" }
	for _, id := range []string{"balanced", "fast", "windscribe", "windscribe-aether", "aether", "psiphon", "tor"} {
		var cfg smartproxy.Config
		Configure(id, &cfg, protected)
		if cfg.ExitOnly == nil || !cfg.ExitOnly("chatgpt.com") {
			t.Fatalf("mode %s disabled protected exit rule", id)
		}
		isForeignOnly := id == "aether" || id == "psiphon" || id == "tor"
		if cfg.ExitOnly("example.com") != isForeignOnly {
			t.Fatalf("mode %s changed foreign-only behavior", id)
		}
		if id == "fast" && cfg.Stagger != 125*time.Millisecond {
			t.Fatal("Fast CLI stagger differs on Android")
		}
		if id == "windscribe" && (!cfg.LocalOnly || !cfg.RejectExits) {
			t.Fatal("Windscribe direct-only policy changed")
		}
	}
}

func TestMixedModesKeepTikTokAPIsAndMediaOnAVerifiedExit(t *testing.T) {
	for _, mode := range []string{"balanced", "fast"} {
		var cfg smartproxy.Config
		Configure(mode, &cfg, func(host string) bool { return host == "chatgpt.com" })
		for _, host := range []string{"www.tiktok.com", "v16-webapp-prime.tiktok.com", "api16.tiktokv.com", "mon16.tiktokv.eu", "location.tiktokw.eu", "sf.tiktokcdn.com", "p16.tiktokcdn-eu.com", "lf16.tiktokcdn-us.com", "sf16.ttwstatic.com", "WWW.TIKTOK.COM.", "chatgpt.com"} {
			if !cfg.ExitOnly(host) {
				t.Fatalf("%s allowed region-sensitive API/media on the ISP route: %s", mode, host)
			}
		}
		for _, host := range []string{"x.com", "example.com", "not-tiktok.com", "tiktok.com.evil.test", "shared-cdn.example"} {
			if cfg.ExitOnly(host) {
				t.Fatalf("%s unnecessarily restricted %s", mode, host)
			}
		}
	}
}
