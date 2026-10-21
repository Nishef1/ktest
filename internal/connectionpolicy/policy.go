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

// allModes is every CLI mode with its shared title, in terminal order.
func allModes() []Mode {
	return []Mode{
		{"balanced", "Balanced", "Local routes first; automatic Aether / Psiphon / Tor fallback", true,
			"Zapret2 is Windows-only."},
		{"fast", "Fast", "Every local method, fronting and learned priors; native exits on demand", true,
			"No Psiphon, Tor or unidentified external SOCKS."},
		{"aether", "Aether", "Packaged MASQUE / WireGuard core", true,
			"Aether handles enrollment, scans and reconnect."},
		{"tor", "Aether to Tor", "Tor alone (no WARP), dialing through Fast's local anti-DPI", true,
			"Requires a verified Tor circuit and foreign exit. First connection can take several minutes."},
		{"windscribe", "Windscribe", "Local-only anti-DPI bridge", false,
			"The desktop WStunnel, Xray and ByeDPI orchestration is not ported."},
		{"psiphon", "Aether to Psiphon", "Psiphon alone (no WARP) through Fast's local anti-DPI, with CDN fronting on verified edges", true,
			"No WARP needed; CDN mode uses edges this network verified first. No external SOCKS substitution."},
		{"windscribe-aether", "Windscribe through Aether", "WARP carrier for Windscribe", false,
			"Requires the genuine Aether carrier and Windscribe bridge; no Android port yet."},
	}
}

// AndroidModes is what the phone offers: the CLI modes that actually work
// there, with the terminal's names and order. Windscribe needs the desktop
// bridge and its own app's cooperation, so it is not listed at all rather
// than shown as a disabled card.
func AndroidModes() []Mode {
	var out []Mode
	for _, m := range allModes() {
		if m.ID != "windscribe" && m.ID != "windscribe-aether" {
			out = append(out, m)
		}
	}
	return out
}

// Title is used by both clients; unknown modes never become made-up modes.
func Title(id string) string {
	for _, m := range allModes() {
		if m.ID == id {
			return m.Title
		}
	}
	return "Unknown"
}

// Configure applies the exact CLI routing policies to a Go smart proxy.
// Transport launch, availability and Windscribe-specific validation are
// separate from this policy function.
func Configure(id string, cfg *smartproxy.Config) {
	switch id {
	case "balanced", "fast":
		cfg.MaxParallel = 6
		cfg.RecoverPinnedExit = true
		// A short head start: the learned or tested first choice usually
		// answers at once, and otherwise the next methods are already racing.
		if cfg.Stagger == 0 || cfg.Stagger > 200*time.Millisecond {
			cfg.Stagger = 200 * time.Millisecond
		}
		if id == "fast" {
			cfg.Stagger = 125 * time.Millisecond
		}
	case "windscribe":
		cfg.PreferVerifiedExit = false
		cfg.RejectExits = true
		cfg.LocalOnly = true
	case "aether", "windscribe-aether":
		// Like PattNG: a working WARP carries every destination, wherever
		// its IP geolocates. No site is singled out; the user decides.
		// Windscribe through Aether has no direct path at all: its OpenVPN
		// rides the WARP carrier, which Windscribe then wraps.
		cfg.ExitRequired = func(string) bool { return true }
	case "psiphon", "tor":
		cfg.ExitOnly = func(string) bool { return true }
	}
}
