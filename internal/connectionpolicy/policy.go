// Package connectionpolicy owns the policy decisions and connection labels
// shared by the ktest terminal and Android UI. It does not start any engine.
package connectionpolicy

import (
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

// Mode is the stable CLI mode identifier; Android must not invent new modes.
type Mode struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Subtitle   string `json:"subtitle"`
	Available  bool   `json:"available"`
	Limitation string `json:"limitation,omitempty"`
}

// AndroidModes uses the terminal's current mode names and preserves its
// order. Available refers to a *functioning mobile proxy entry point*, not
// equivalence with the full Windows orchestration or device VPN coverage.
func AndroidModes() []Mode {
	return []Mode{
		{"balanced", "Balanced", "Local routes first; automatic Aether / Psiphon / Tor fallback", true,
			"Zapret2 is Windows-only. Protected services require a verified foreign exit."},
		{"fast", "Fast", "Every local method, fronting and learned priors; native exits on demand", true,
			"No Psiphon, Tor or unidentified external SOCKS. Protected services still require a verified foreign exit."},
		{"aether", "Aether", "Packaged MASQUE / WireGuard core", true,
			"Aether handles enrollment, scans and reconnect. A verified foreign exit is required."},
		{"tor", "Aether to Tor", "Tor alone (no WARP), dialing through Fast's local anti-DPI; no WARP", true,
			"Requires a verified Tor circuit and foreign exit. First connection can take several minutes."},
		{"windscribe", "Windscribe", "Local-only anti-DPI bridge", false,
			"The desktop WStunnel, Xray and ByeDPI orchestration is not ported."},
		{"psiphon", "Aether to Psiphon", "Psiphon alone (no WARP) through Fast's local anti-DPI, with CDN fronting on verified edges", true,
			"No WARP needed; CDN mode uses edges this network verified first. No external SOCKS substitution."},
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
	case "balanced", "fast":
		cfg.MaxParallel = 6
		cfg.RecoverPinnedExit = true
		cfg.ExitOnly = func(host string) bool {
			return tiktokRequiresForeignExit(host) || (protected != nil && protected(host))
		}
		// A short head start: the learned or tested first choice usually
		// answers at once, and otherwise the next methods are already racing.
		if cfg.Stagger == 0 || cfg.Stagger > 200*time.Millisecond {
			cfg.Stagger = 200 * time.Millisecond
		}
		if id == "fast" {
			cfg.Stagger = 125 * time.Millisecond
		}
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

// These dedicated TikTok API, static and media domains were observed together
// in the working foreign-exit browser flow. Local DPI bypass preserves the ISP
// exit and can win a TLS race while the service refuses or stalls its content.
// Keep the entire service on the session's verified foreign path. Shared CDN
// providers and unrelated ByteDance services are intentionally not matched.
func tiktokRequiresForeignExit(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, domain := range []string{"tiktok.com", "tiktokv.com", "tiktokv.eu", "tiktokw.eu", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokcdn-eu.com", "ttwstatic.com"} {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}
