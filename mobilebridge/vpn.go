// Package mobilebridge exposes the KTest Go core to Android's UI and
// VpnService. The Android platform does not choose network strategies.
package mobilebridge

import (
	"encoding/json"
	"errors"
	"sync"
)

// AndroidVpnPacketAdapter is the OS-specific packet forwarding hook.
//
// Implementations receive the fd *owned by Android VpnService* and must only
// run the packet dataplane, not choose routes or launch an independent VPN
// core. Importantly, Start MUST fail if the supplied SOCKS endpoint cannot
// carry the required IPv4, IPv6, DNS and UDP traffic.
//
// All methods intentionally use gomobile-bind-compatible primitive types.
type AndroidVpnPacketAdapter interface {
	Start(fd int, socksAddress string) bool
	Stop()
	IsRunning() bool
	SupportsUDP() bool
	SupportsIPv6() bool
}

// vpnTunPlan contains the address/route policy owned by the Go core. The
// Kotlin VpnService only translates these values to Android Builder calls.
// These values are not enabled until the packet-forwarding gate passes.
type vpnTunPlan struct {
	MTU         int    `json:"mtu"`
	IPv4Address string `json:"ipv4_address"`
	IPv4Prefix  int    `json:"ipv4_prefix"`
	IPv6Address string `json:"ipv6_address"`
	IPv6Prefix  int    `json:"ipv6_prefix"`
	IPv4Route   string `json:"ipv4_route"`
	IPv6Route   string `json:"ipv6_route"`
	IPv4DNS     string `json:"ipv4_dns"`
	IPv6DNS     string `json:"ipv6_dns"`
}

var defaultTunPlan = vpnTunPlan{
	MTU:         1280,
	IPv4Address: "172.19.0.1", IPv4Prefix: 30,
	IPv6Address: "fdfe:dcba:9876::1", IPv6Prefix: 126,
	IPv4Route: "0.0.0.0", IPv6Route: "::",
	IPv4DNS: "1.1.1.1", IPv6DNS: "2606:4700:4700::1111",
}

// VpnTunPlan is Android's OS-level configuration translation input. The
// existing Go networking core remains the single source of route policy.
func VpnTunPlan() string {
	raw, err := json.Marshal(defaultTunPlan)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

type vpnReport struct {
	Available              bool   `json:"available"`
	Active                 bool   `json:"active"`
	ProxyRunning           bool   `json:"proxy_running"`
	PacketAdapterInstalled bool   `json:"packet_adapter_installed"`
	UDPReady               bool   `json:"udp_ready"`
	IPv6Ready              bool   `json:"ipv6_ready"`
	SOCKSUDPImplemented    bool   `json:"socks_udp_implemented"`
	PacketDNSImplemented   bool   `json:"packet_dns_implemented"`
	Reason                 string `json:"reason"`
}

var vpnMu sync.Mutex
var packetAdapter AndroidVpnPacketAdapter
var vpnActive bool

// The Android packet path (HEV tun2socks -> Go SOCKS with UDP ASSOCIATE and
// encrypted packet DNS) is enabled as a user-consented beta. Non-DNS UDP is
// still only relayed through a verified foreign exit and never sent directly,
// so apps fall back to TCP where a mode cannot carry UDP. These remain
// variables so tests and future regressions can close the gate again.
var coreSOCKSUDPReady = true
var coreIPv6VPNReady = true

// SetAndroidVpnPacketAdapter registers an OS-only packet adapter. No transport
// or policy is implemented here. Once a native driver exists, Android calls
// this before requesting VpnService.prepare().
func SetAndroidVpnPacketAdapter(adapter AndroidVpnPacketAdapter) {
	vpnMu.Lock()
	if vpnActive {
		vpnMu.Unlock()
		return // Cannot swap the dataplane under a running VPN.
	}
	packetAdapter = adapter
	vpnMu.Unlock()
}

func vpnReportLocked() vpnReport {
	proxyMu.Lock()
	running := activeProxy != nil
	proxyMu.Unlock()
	state := vpnReport{
		ProxyRunning:           running,
		PacketAdapterInstalled: packetAdapter != nil,
		UDPReady:               coreSOCKSUDPReady,
		IPv6Ready:              coreIPv6VPNReady,
		Active:                 vpnActive,
		SOCKSUDPImplemented:    true,
		PacketDNSImplemented:   true,
	}
	switch {
	case !running:
		state.Reason = "Start the existing Go connection core first."
	case !coreSOCKSUDPReady:
		state.Reason = "Go SOCKS UDP and encrypted packet DNS are implemented; a live dual-stack UDP exit and Android HEV/TUN path are not validated yet."
	case !coreIPv6VPNReady:
		state.Reason = "IPv6 whole-device routing has not been validated."
	case packetAdapter == nil:
		state.Reason = "Android TUN packet adapter has not been registered."
	case !packetAdapter.SupportsUDP() || !packetAdapter.SupportsIPv6():
		state.Reason = "TUN adapter lacks required UDP or IPv6 packet support."
	default:
		state.Available = true
		if vpnActive {
			if !packetAdapter.IsRunning() {
				state.Active = false
				state.Reason = "Packet adapter stopped; VPN traffic is not verified."
			} else {
				state.Reason = "Packet adapter is running; verify actual traffic and DNS before claiming connectivity."
			}
		} else {
			state.Reason = "Packet routing is available (beta); Android VPN permission is required."
		}
	}
	return state
}

// VpnCapability is a machine-readable *live capability check*, not a promise
// that a tun session or network egress exists. Used by Android UI and service.
func VpnCapability() string {
	vpnMu.Lock()
	state := vpnReportLocked()
	vpnMu.Unlock()
	body, err := json.Marshal(state)
	if err != nil {
		return `{"available":false,"active":false,"reason":"VPN status is unavailable"}`
	}
	return string(body)
}

// AttachVpnTun is called only AFTER Android consent + Builder.establish().
// The core rejects unsupported packet transport BEFORE touching the tun fd.
// Protocol support alone does not establish full-device UDP/DNS readiness.
func AttachVpnTun(fd int) error {
	if fd < 0 {
		return errors.New("invalid Android TUN file descriptor")
	}
	vpnMu.Lock()
	defer vpnMu.Unlock()
	state := vpnReportLocked()
	if !state.Available {
		return errors.New(state.Reason)
	}
	if vpnActive {
		return errors.New("Android VPN dataplane is already running")
	}
	proxyMu.Lock()
	endpoint := activeProxy.socks.Addr().String()
	proxyMu.Unlock()
	if !packetAdapter.Start(fd, endpoint) || !packetAdapter.IsRunning() {
		packetAdapter.Stop()
		return errors.New("Android packet adapter did not become healthy")
	}
	vpnActive = true
	return nil
}

// StopVpnTun owns packet adapter shutdown; Android owns and must close the fd.
func StopVpnTun() {
	vpnMu.Lock()
	if !vpnActive {
		vpnMu.Unlock()
		return
	}
	driver := packetAdapter
	vpnActive = false
	vpnMu.Unlock()
	if driver != nil {
		driver.Stop()
	}
}
