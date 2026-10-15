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
			"address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
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
