package systemtun

import (
	"encoding/json"
	"errors"
)

// BuildConfig is intentionally TCP-first and fail-closed for unspecified UDP.
// It blocks traffic targeting the TUN's own gateway to prevent known Windows
// routing loops. Outbound packet injection remains in the already-running
// Xray/ByeDPI process; this layer only transparently forwards the traffic.
func BuildConfig(socksPort int, physicalNIC string) ([]byte, error) {
	if socksPort < 1 || socksPort > 65535 {
		return nil, errors.New("invalid local SOCKS port")
	}
	if physicalNIC == "" {
		return nil, errors.New("physical interface is required to prevent routing loops")
	}
	root := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "tun", "tag": "ktest-tun", "interface_name": "ktest-tun",
			"address":    []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"auto_route": true, "strict_route": true, "dns_mode": "hijack",
			"stack": "gvisor",
		}},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"type": "https", "tag": "doh", "server": "8.8.8.8", "path": "/dns-query", "detour": "socks"},
			},
			"final": "doh", "strategy": "prefer_ipv4",
		},
		"outbounds": []any{
			map[string]any{"type": "socks", "tag": "socks", "server": "127.0.0.1", "server_port": socksPort, "version": "5", "network": "tcp"},
			map[string]any{"type": "direct", "tag": "physical", "bind_interface": physicalNIC},
		},
		"route": map[string]any{
			"rules": []any{
				map[string]any{"port": 53, "action": "hijack-dns"},
				map[string]any{"ip_cidr": []string{"172.19.0.0/30", "fdfe:dcba:9876::/126"}, "action": "reject", "method": "drop"},
				map[string]any{"process_name": []string{"xray.exe", "ciadpi.exe"}, "action": "route", "outbound": "physical"},
				map[string]any{"ip_is_private": true, "action": "route", "outbound": "physical"},
				map[string]any{"network": "udp", "action": "reject", "method": "drop"},
			},
			"final": "socks",
		},
	}
	return json.MarshalIndent(root, "", "  ")
}

// Options describes a system-wide tunnel that feeds the ktest Connect proxy.
type Options struct {
	// SocksPort is the local SOCKS5 port of the proxy that carries everything.
	SocksPort int
	// PhysicalNIC is the real network interface; sockets that must not enter the
	// tunnel are bound to it.
	PhysicalNIC string
	// DirectProcesses leave on the physical interface untouched: the proxy
	// itself and the cores it runs, otherwise their own connections would be
	// routed back into the tunnel and loop.
	DirectProcesses []string
	// BlockPageCIDRs are private ranges that a poisoning resolver answers with
	// (Iran: 10.10.34.0/24). They are not the LAN; they go to the proxy, which
	// recovers the real name from the TLS SNI.
	BlockPageCIDRs []string
}

// DefaultBlockPage is the block-page range seen on Iranian networks.
var DefaultBlockPage = []string{"10.10.34.0/24"}

// BuildSystemConfig builds the sing-box configuration of the system-wide
// tunnel. Names are answered with fake addresses from a private pool and mapped
// back when the connection arrives, so the proxy always receives the real host
// name and the (poisoned or filtered) DNS is never consulted by applications.
// TCP only: UDP other than DNS is dropped so that applications fall back to TCP.
func BuildSystemConfig(o Options) ([]byte, error) {
	if o.SocksPort < 1 || o.SocksPort > 65535 {
		return nil, errors.New("invalid local SOCKS port")
	}
	if o.PhysicalNIC == "" {
		return nil, errors.New("physical interface is required to prevent routing loops")
	}
	if len(o.DirectProcesses) == 0 {
		return nil, errors.New("the proxy's own processes must be exempt from the tunnel, or it would loop")
	}
	block := o.BlockPageCIDRs
	if block == nil {
		block = DefaultBlockPage
	}
	rules := []any{
		// Our own sockets first, before DNS hijacking, so that the proxy's name
		// lookups and connections reach the real network.
		map[string]any{"process_name": o.DirectProcesses, "action": "route", "outbound": "physical"},
		map[string]any{"ip_cidr": []string{"172.19.0.0/30", "fdfe:dcba:9876::/126"}, "action": "reject", "method": "drop"},
		map[string]any{"port": 53, "action": "hijack-dns"},
	}
	if len(block) > 0 {
		rules = append(rules, map[string]any{"ip_cidr": block, "action": "route", "outbound": "ktest"})
	}
	rules = append(rules,
		map[string]any{"ip_is_private": true, "action": "route", "outbound": "physical"},
		map[string]any{"network": "udp", "action": "reject", "method": "drop"},
	)
	root := map[string]any{
		"log": map[string]any{"level": "warn"},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"type": "local", "tag": "local"},
				map[string]any{"type": "fakeip", "tag": "fake", "inet4_range": "198.18.0.0/15"},
			},
			"rules": []any{map[string]any{"query_type": []string{"A", "AAAA"}, "action": "route", "server": "fake"}},
			"final": "local",
		},
		"inbounds": []any{map[string]any{
			"type": "tun", "tag": "ktest-tun", "interface_name": "ktest-tun",
			"address":    []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"auto_route": true, "strict_route": true, "stack": "gvisor",
		}},
		"outbounds": []any{
			map[string]any{"type": "socks", "tag": "ktest", "server": "127.0.0.1", "server_port": o.SocksPort, "version": "5", "network": "tcp"},
			map[string]any{"type": "direct", "tag": "physical", "bind_interface": o.PhysicalNIC},
		},
		"route": map[string]any{"rules": rules, "final": "ktest", "auto_detect_interface": true, "default_domain_resolver": "local"},
	}
	return json.MarshalIndent(root, "", "  ")
}
