// Package connectionpolicy owns the policy decisions and connection labels
// shared by the ktest terminal and Android UI. It does not start any engine.
package connectionpolicy

import (
    "time"

    "github.com/Nishef1/ktest/internal/smartproxy"
)

// Mode is the stable CLI mode identifier; Android must not invent new modes.
type Mode struct {
    ID string `json:"id"`
    Title string `json:"title"`
    Subtitle string `json:"subtitle"`
    Available bool `json:"available"`
    Limitation string `json:"limitation,omitempty"`
}

// AndroidModes uses the terminal's current mode names and preserves its
// order. Available refers to a *functioning mobile proxy entry point*, not
// equivalence with the full Windows orchestration or device VPN coverage.
func AndroidModes() []Mode {
    return []Mode{
        {"balanced", "Balanced", "Adaptive Go routes; AI needs verified exit", true,
            "The Windows Xray/ByeDPI/fronting strategy bundle is not fully ported."},
        {"fast", "Fast", "Faster Go route selection; AI exit still required", true,
            "Not equivalent to all Windows desktop strategies."},
        {"aether", "Aether", "Bring a local Aether SOCKS5 exit", true,
            "Only the CLI's optional -exit-socks path is supported on Android; no managed WARP/MASQUE core."},
        {"tor", "Aether to Tor", "Embedded Tor-only TCP proxy", true,
            "Tor is embedded but is not chained through the managed desktop Aether core; no UDP VPN."},
        {"windscribe", "Windscribe", "Local-only anti-DPI bridge", false,
            "The desktop WStunnel, Xray and ByeDPI orchestration is not ported."},
        {"psiphon", "Aether to Psiphon", "Managed Psiphon profiles only", false,
            "CLI forbids external -exit-socks here. Android needs the managed Aether Psiphon core."},
        {"windscribe-aether", "Windscribe through Aether", "WARP carrier for Windscribe", false,
            "Requires the genuine Aether carrier and Windscribe bridge; no Android port yet."},
    }
}

// Title is used by both clients; unknown modes never become made-up modes.
func Title(id string) string {
    for _, m := range AndroidModes() {
        if m.ID == id {
            return m.Title
        }
    }
    return "Unknown"
}

// Configure applies the exact CLI routing policies to a Go smart proxy.
// Transport launch, availability and Windscribe-specific validation are
// separate from this policy function.
func Configure(id string, cfg *smartproxy.Config, protected func(string) bool) {
    switch id {
    case "balanced":
        cfg.ExitOnly = protected
    case "fast":
        cfg.ExitOnly = protected
        cfg.Stagger = 125 * time.Millisecond
    case "windscribe":
        cfg.ExitOnly = protected
        cfg.PreferVerifiedExit = false
        cfg.RejectExits = true
        cfg.LocalOnly = true
    case "windscribe-aether":
        cfg.ExitOnly = protected
    case "aether", "psiphon", "tor":
        cfg.ExitOnly = func(string) bool { return true }
    }
}
