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

const (
	ModeBalanced   ConnectionMode = "balanced"   // current convenience: AI needs exit
	ModeFast       ConnectionMode = "fast"       // fastest usable; identity may change
	ModeWindscribe ConnectionMode = "windscribe" // bootstrap, real VPN is external
	ModeVPN        ConnectionMode = "vpn"        // verified foreign exits only
	ModeTor        ConnectionMode = "tor"        // verified Tor exit only
)

func parseConnectionMode(v string) (ConnectionMode, error) {
	m := ConnectionMode(strings.ToLower(strings.TrimSpace(v)))
	switch m {
	case ModeBalanced, ModeFast, ModeWindscribe, ModeVPN, ModeTor:
		return m, nil
	default:
		return "", fmt.Errorf("unknown -mode %q; use balanced, fast, windscribe, vpn, or tor", v)
	}
}

func (m ConnectionMode) configure(cfg *smartproxy.Config, rules *smartproxy.DomainRules) {
	switch m {
	case ModeBalanced:
		cfg.ExitOnly = rules.Match
	case ModeFast:
		cfg.ExitOnly = nil
		cfg.Stagger = 125 * time.Millisecond
	case ModeWindscribe:
		cfg.ExitOnly = nil
		cfg.PreferVerifiedExit = false
		cfg.RejectExits = true
		cfg.LocalOnly = true
	case ModeVPN, ModeTor:
		cfg.ExitOnly = func(string) bool { return true }
	}
}

func (m ConnectionMode) message() string {
	switch m {
	case ModeBalanced:
		return "Mixed routing; AI domains require verified foreign exit and fail closed."
	case ModeFast:
		return "Speed first: direct, fronting, desync and VPN exits can win; public IP may change by site."
	case ModeWindscribe:
		return "IP-preserving local anti-DPI only (ByeDPI/ClientHello desync). Psiphon, Aether, WARP, Tor, plain and remote exits OFF. Windscribe controls public VPN IP."
	case ModeVPN:
		return "Exit-only: one verified foreign upstream pinned for this session; no direct fallback for managed apps."
	case ModeTor:
		return "Tor-only: no direct fallback for managed apps. Different Tor circuits can use different public IPs."
	}
	return "Unknown"
}
