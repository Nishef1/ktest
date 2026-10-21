package connectionpolicy

import (
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

func TestModeCatalogIsUniqueAndFaithfulToCLI(t *testing.T) {
	expected := []string{"balanced", "fast", "aether", "tor", "psiphon"}
	modes := AndroidModes()
	if len(modes) != len(expected) {
		t.Fatalf("expected %d modes, got %d", len(expected), len(modes))
	}
	for i, m := range modes {
		if m.ID != expected[i] || m.Title == "" || m.Subtitle == "" || m.Details == "" {
			t.Fatalf("mode %d mismatches CLI: %+v", i, m)
		}
		if m.Available && m.Limitation == "" {
			t.Fatalf("partial Android port missing caveat: %q", m.ID)
		}
	}
	if Title("tor") != "Aether to Tor" || Title("psiphon") != "Aether to Psiphon" || Title("windscribe") != "Windscribe" {
		t.Fatal("Android silently renamed a desktop CLI policy")
	}
}

// No site is singled out in any mode: AI and TikTok route like the rest.
// Psiphon and Tor send everything through their exit; Aether carries
// everything on any working exit, and so does Windscribe through Aether.
func TestConfigureMatchesCLIForAllModes(t *testing.T) {
	for _, id := range []string{"balanced", "fast", "windscribe", "windscribe-aether", "aether", "psiphon", "tor"} {
		var cfg smartproxy.Config
		Configure(id, &cfg)
		exitOnly := id == "psiphon" || id == "tor"
		if (cfg.ExitOnly != nil) != exitOnly {
			t.Fatalf("mode %s: ExitOnly set=%v", id, cfg.ExitOnly != nil)
		}
		for _, host := range []string{"chatgpt.com", "www.tiktok.com", "example.com"} {
			if exitOnly && !cfg.ExitOnly(host) {
				t.Fatalf("mode %s let %s off its exit", id, host)
			}
		}
		if required := cfg.ExitRequired != nil && cfg.ExitRequired("chatgpt.com"); required != (id == "aether" || id == "windscribe-aether") {
			t.Fatalf("mode %s: ExitRequired=%v", id, required)
		}
		if id == "fast" && cfg.Stagger != 125*time.Millisecond {
			t.Fatal("Fast CLI stagger differs on Android")
		}
		if id == "windscribe" && (!cfg.LocalOnly || !cfg.RejectExits) {
			t.Fatal("Windscribe direct-only policy changed")
		}
	}
}

// Exit modes start with no upstream: their exits (WARP, Psiphon, Tor) join
// once found. Each must still build a proxy, or connect stops at once.
func TestExitModesStartWithoutUpstreams(t *testing.T) {
	for _, id := range []string{"aether", "windscribe-aether", "psiphon", "tor"} {
		var cfg smartproxy.Config
		Configure(id, &cfg)
		if _, err := smartproxy.New(cfg); err != nil {
			t.Fatalf("mode %s: %v", id, err)
		}
	}
}
