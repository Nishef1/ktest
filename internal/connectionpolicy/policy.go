// Package connectionpolicy owns the policy decisions and connection labels
// shared by the ktest terminal and Android UI. It does not start any engine.
package connectionpolicy

import (
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
		{"balanced", "Balanced", "Adaptive routes; protected AI traffic", true,
			"Some desktop strategies are not yet available on Android."},
		{"fast", "Fast", "Faster routes; protected AI traffic", true,
			"Some desktop strategies are not yet available on Android."},
		{"aether", "Aether", "Packaged MASQUE / WireGuard core", true,
			"Aether handles enrollment, scans and reconnect. A verified foreign exit is required."},
		{"tor", "Aether to Tor", "Aether's built-in Tor backend", true,
			"Requires a verified Tor circuit and foreign exit. First connection can take several minutes."},
		{"windscribe", "Windscribe", "Local-only anti-DPI bridge", false,
			"The desktop WStunnel, Xray and ByeDPI orchestration is not ported."},
		{"psiphon", "Aether to Psiphon", "Psiphon with optional CDN fronting", true,
			"Uses Aether's bundled Psiphon backend, including CDN mode; no external SOCKS substitution."},
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
