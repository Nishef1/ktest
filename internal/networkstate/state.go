package networkstate

import (
	"context"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Result is a warning, not a proof that no VPN is in use. Some commercial
// clients support application-specific routing invisible to a simple adapter
// scan. In the presence of doubt we refuse to attribute success to ktest.
type Result struct {
	Suspected    bool
	ClientOpen   bool
	Reasons      []string
	Observations []string
}

var suspiciousNames = []string{
	"windscribe", "wireguard", "wintun", "openvpn", "tap-windows",
	"amnezia", "tailscale", "nordlynx", "protonvpn", "zerotier",
	"tun0", "utun", "ktest-tun",
}

func Inspect(ctx context.Context) Result {
	var result Result
	interfaces, err := net.Interfaces()
	if err != nil {
		result.Suspected = true
		result.Reasons = append(result.Reasons, "could not enumerate network adapters")
	} else {
		for _, item := range interfaces {
			if item.Flags&net.FlagUp == 0 || item.Flags&net.FlagLoopback != 0 {
				continue
			}
			name := strings.ToLower(item.Name)
			for _, indicator := range suspiciousNames {
				if strings.Contains(name, indicator) {
					result.Suspected = true
					result.Reasons = append(result.Reasons, "active virtual/VPN interface: "+item.Name)
					break
				}
			}
		}
	}
	// A running Windscribe GUI is not evidence of a connected VPN.
	// Preserve it as informational only; identify probable active VPNs through
	// adapters. Split tunneling can still evade heuristic detection.
	if runtime.GOOS == "windows" {
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		cmd := exec.CommandContext(probeCtx, "powershell.exe", "-NoProfile", "-NonInteractive",
			"-Command", "$p=Get-Process -Name 'Windscribe*' -ErrorAction SilentlyContinue; if ($p) { 'RUNNING' }")
		output, err := cmd.Output()
		if err == nil && strings.Contains(string(output), "RUNNING") {
			result.ClientOpen = true
			result.Observations = append(result.Observations, "Windscribe application open; connection status unknown")
		}
	}
	return result
}
