package mobilebridge

import (
    "testing"
    "github.com/Nishef1/ktest/internal/connectionpolicy"
    "github.com/Nishef1/ktest/internal/smartproxy"
)

func TestExternalModesFailClosedForEveryDestination(t *testing.T) {
    named := func(host string) bool { return host == "chatgpt.com" }
    for _, mode := range []string{"aether", "psiphon", "tor"} {
        cfg := smartproxy.Config{}
        connectionpolicy.Configure(mode, &cfg, named)
        only := cfg.ExitOnly
        for _, host := range []string{"chatgpt.com", "example.net", "203.0.113.3", ""} {
            if !only(host) { t.Fatalf("%s should require verified exit for %q", mode, host) }
        }
    }
    for _, mode := range []string{"balanced", "fast"} {
        cfg := smartproxy.Config{}
        connectionpolicy.Configure(mode, &cfg, named)
        only := cfg.ExitOnly
        if !only("chatgpt.com") || only("example.net") {
            t.Fatalf("%s should preserve per-host protected domain policy", mode)
        }
    }
}
