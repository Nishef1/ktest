package mobilebridge

import "testing"

func TestExternalModesFailClosedForEveryDestination(t *testing.T) {
    named := func(host string) bool { return host == "chatgpt.com" }
    for _, mode := range []string{"aether", "psiphon", "tor"} {
        only := exitOnlyForMode(mode, named)
        for _, host := range []string{"chatgpt.com", "example.net", "203.0.113.3", ""} {
            if !only(host) { t.Fatalf("%s should require verified exit for %q", mode, host) }
        }
    }
    for _, mode := range []string{"balanced", "fast"} {
        only := exitOnlyForMode(mode, named)
        if !only("chatgpt.com") || only("example.net") {
            t.Fatalf("%s should preserve per-host protected domain policy", mode)
        }
    }
}
