package connectionpolicy

import (
    "testing"
    "time"

    "github.com/Nishef1/ktest/internal/smartproxy"
)

func TestModeCatalogIsUniqueAndFaithfulToCLI(t *testing.T) {
    expected := []string{"balanced", "fast", "aether", "tor", "windscribe", "psiphon", "windscribe-aether"}
    modes := AndroidModes()
    if len(modes) != len(expected) { t.Fatalf("expected %d modes, got %d", len(expected), len(modes)) }
    for i, m := range modes {
        if m.ID != expected[i] || m.Title == "" || m.Subtitle == "" {
            t.Fatalf("mode %d mismatches CLI: %+v", i, m)
        }
        if m.Available && m.Limitation == "" { t.Fatalf("partial Android port missing caveat: %q", m.ID) }
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
