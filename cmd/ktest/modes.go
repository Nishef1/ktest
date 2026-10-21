package main

import (
	"fmt"
	"github.com/Nishef1/ktest/internal/connectionpolicy"
	"github.com/Nishef1/ktest/internal/smartproxy"
	"strings"
)

// ConnectionMode is an explicit user choice, never inferred from an open port.
// Modes control ktest's managed SOCKS/HTTP traffic, not arbitrary OS sockets.
type ConnectionMode string

func connectionCoverage(o connectOptions) string {
	if o.mode.isWindscribe() {
		return "Windscribe app only; configure its HTTP proxy; Windscribe owns system coverage"
	}
	if o.tun && o.mode.tunUDP() {
		return "Whole PC TCP and UDP via TUN; UDP (QUIC, calls) rides the WARP exit; LAN/helpers exempt; activation is verified separately"
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
	ModeAether           ConnectionMode = "aether"            // verified WARP exits only
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

func (m ConnectionMode) allowsXray() bool {
	return !m.exitOnly()
}

// tunUDP: in Aether every destination rides an exit, and Aether relays SOCKS5
// UDP ASSOCIATE through the tunnel, so the system tunnel sends UDP there
// instead of rejecting it. Other modes have no guaranteed UDP-capable exit.
func (m ConnectionMode) tunUDP() bool { return m == ModeAether }

func (m ConnectionMode) isWindscribe() bool { return m == ModeWindscribe || m == ModeWindscribeAether }

func (m ConnectionMode) configure(cfg *smartproxy.Config, rules *smartproxy.DomainRules) {
	connectionpolicy.Configure(string(m), cfg, rules.Match)
}

func (m ConnectionMode) message() string {
	switch m {
	case ModeBalanced:
		return "Local routes first; on-demand Aether, Psiphon and Tor fallback. TikTok and AI require a verified foreign exit."
	case ModeFast:
		return "Local Go, ByeDPI, Xray, Zapret and fronting routes with learned priors; Aether exits on demand, no Psiphon or Tor. TikTok and AI require a verified foreign exit."
	case ModeWindscribe:
		return "OpenVPN TCP re-wrapped in Windscribe WStunnel (chosen SNI, optional own Cloudflare hostname) plus IP-preserving local anti-DPI (Xray TCP fragmentation, ByeDPI, TLS ClientHello desync). Psiphon, Aether, WARP, Tor, plain and remote exits OFF. Windscribe controls public VPN IP."
	case ModeWindscribeAether:
		return "WARP through Aether carries Windscribe OpenVPN TCP. Keep Aether running and exclude ktest/aether from Windscribe split tunneling. No direct, Psiphon or Tor fallback. Windscribe owns the final VPN exit."
	case ModeAether:
		return "Aether: search WARP MASQUE/WireGuard profiles only; registers missing keys over ECH first; sites use any working WARP exit, AI and TikTok need one outside Iran."
	case ModePsiphon:
		return "Aether to Psiphon: Psiphon profiles only; verified foreign exit required; no WARP, Tor or direct fallback for managed apps."
	case ModeTor:
		return "Aether to Tor: Tor-only; no direct fallback for managed apps. Different Tor circuits can use different public IPs."
	}
	return "Unknown"
}
