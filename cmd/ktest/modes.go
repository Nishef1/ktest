package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

// ConnectionMode is an explicit user choice, never inferred from an open port.
// Modes control ktest's managed SOCKS/HTTP traffic, not arbitrary OS sockets.
type ConnectionMode string

func connectionCoverage(o connectOptions) string {
	if o.mode.isWindscribe() {
		return "Windscribe app only; configure its HTTP proxy; Windscribe owns system coverage"
	}
	if o.tun {
		return "Whole PC TCP requested via TUN; LAN/helpers exempt, most UDP blocked; activation is verified separately"
	}
	return "Proxy apps only; configure SOCKS5/HTTP in each app; other applications keep their own route"
}

const (
	ModeBalanced         ConnectionMode = "balanced"          // current convenience: AI needs exit
	ModeFast             ConnectionMode = "fast"              // fastest usable; identity may change
	ModeWindscribe       ConnectionMode = "windscribe"        // bootstrap, real VPN is external
	ModeWindscribeAether ConnectionMode = "windscribe-aether" // explicit WARP carrier for OpenVPN TCP
	ModeAether           ConnectionMode = "aether"            // verified WARP/Psiphon exits only
	ModePsiphon          ConnectionMode = "psiphon"           // Aether's Psiphon profiles only
	ModeTor              ConnectionMode = "tor"               // verified Tor exit only
)

func parseConnectionMode(v string) (ConnectionMode, error) {
	m := ConnectionMode(strings.ToLower(strings.TrimSpace(v)))
	switch m {
	case ModeBalanced, ModeFast, ModeWindscribe, ModeWindscribeAether, ModeAether, ModePsiphon, ModeTor:
		return m, nil
	default:
		return "", fmt.Errorf("unknown -mode %q; use balanced, fast, windscribe, windscribe-aether, aether, psiphon, or tor", v)
	}
}

func (m ConnectionMode) exitOnly() bool {
	return m == ModeAether || m == ModePsiphon || m == ModeTor || m == ModeWindscribeAether
}

func (m ConnectionMode) isWindscribe() bool { return m == ModeWindscribe || m == ModeWindscribeAether }

func (m ConnectionMode) configure(cfg *smartproxy.Config, rules *smartproxy.DomainRules) {
	switch m {
	case ModeBalanced:
		cfg.ExitOnly = rules.Match
	case ModeFast:
		cfg.ExitOnly = rules.Match
		cfg.Stagger = 125 * time.Millisecond
	case ModeWindscribe:
		cfg.ExitOnly = rules.Match
		cfg.PreferVerifiedExit = false
		cfg.RejectExits = true
		cfg.LocalOnly = true
	case ModeWindscribeAether:
		cfg.ExitOnly = rules.Match // OpenVPN transport is not an AI identity/session
	case ModeAether, ModePsiphon, ModeTor:
		cfg.ExitOnly = func(string) bool { return true }
	}
}

func (m ConnectionMode) message() string {
	switch m {
	case ModeBalanced:
		return "Mixed routing; AI domains require verified foreign exit and fail closed."
	case ModeFast:
		return "Speed first for ordinary sites; AI requires a verified foreign exit and fails closed."
	case ModeWindscribe:
		return "OpenVPN TCP re-wrapped in Windscribe WStunnel (chosen SNI, optional own Cloudflare hostname) plus IP-preserving local anti-DPI (Xray TCP fragmentation, ByeDPI, TLS ClientHello desync). Psiphon, Aether, WARP, Tor, plain and remote exits OFF. Windscribe controls public VPN IP."
	case ModeWindscribeAether:
		return "WARP through Aether carries Windscribe OpenVPN TCP. Keep Aether running and exclude ktest/aether from Windscribe split tunneling. No direct, Psiphon or Tor fallback. Windscribe owns the final VPN exit."
	case ModeAether:
		return "Aether: search WARP/Psiphon profiles; one verified foreign upstream pinned for this session; no direct fallback for managed apps."
	case ModePsiphon:
		return "Aether to Psiphon: Psiphon profiles only; verified foreign exit required; no WARP, Tor or direct fallback for managed apps."
	case ModeTor:
		return "Aether to Tor: Tor-only; no direct fallback for managed apps. Different Tor circuits can use different public IPs."
	}
	return "Unknown"
}
