// Package mobilebridge exposes the KTest Go core to Android's UI and
// VpnService. The Android platform does not choose network strategies.
package mobilebridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// AndroidVpnPacketAdapter is the HEV fallback adapter for Android's TUN fd.
// Implementations only run packet forwarding; they do not choose routes or
// establish a separate Internet exit. The preferred Xray TUN engine is managed
// by Go and sends its flows to the same local SOCKS policy engine.
//
// All methods intentionally use gomobile-bind-compatible primitive types.
type AndroidVpnPacketAdapter interface {
	Start(fd int, socksAddress string) bool
	Stop()
	IsRunning() bool
	SupportsUDP() bool
	SupportsIPv6() bool
}

type androidXrayTun interface {
	AndroidVpnPacketAdapter
	LastError() string
}

// vpnTunPlan contains the address/route policy owned by the Go core. The
// Kotlin VpnService only translates these values to Android Builder calls.
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
	PacketAdapter          string `json:"packet_adapter,omitempty"`
	FallbackReason         string `json:"fallback_reason,omitempty"`
	XrayError              string `json:"xray_error,omitempty"`
	UDPReady               bool   `json:"udp_ready"`
	IPv6Ready              bool   `json:"ipv6_ready"`
	SOCKSUDPImplemented    bool   `json:"socks_udp_implemented"`
	PacketDNSImplemented   bool   `json:"packet_dns_implemented"`
	Reason                 string `json:"reason"`
}

var vpnMu sync.Mutex
var packetAdapter AndroidVpnPacketAdapter // HEV fallback, registered by Android
var xrayTun androidXrayTun                // preferred adapter, pinned Xray TUN -> Go SOCKS
var activePacketAdapter AndroidVpnPacketAdapter
var activeAdapterName string
var vpnTunFD = -1
var vpnSOCKSEndpoint string
var xrayFallbackReason string
var vpnRecoveryAttempts int
var vpnActive bool

// The Go SOCKS path implements UDP ASSOCIATE and encrypted packet DNS.
// Non-DNS UDP is only relayed through a verified foreign exit and never sent
// directly. The Android adapter still has to prove that it can start.
var coreSOCKSUDPReady = true
var coreIPv6VPNReady = true

// SetAndroidVpnPacketAdapter registers HEV as the automatic fallback. No
// transport or routing policy is implemented in this Kotlin adapter.
func SetAndroidVpnPacketAdapter(adapter AndroidVpnPacketAdapter) {
	vpnMu.Lock()
	if vpnActive {
		vpnMu.Unlock()
		return // Cannot swap the dataplane under a running VPN.
	}
	packetAdapter = adapter
	vpnMu.Unlock()
}

// SetAndroidXrayTunPaths configures the pinned Xray TUN adapter. At runtime,
// Go tries Xray first and automatically starts HEV if Xray cannot start or exits.
func SetAndroidXrayTunPaths(nativeDir, privateDir string) {
	vpnMu.Lock()
	defer vpnMu.Unlock()
	if vpnActive {
		return
	}
	if nativeDir == "" || privateDir == "" {
		xrayTun = nil
		return
	}
	xrayTun = newXrayTunPacketAdapter(nativeDir, privateDir)
}

func vpnCandidateAvailable() bool {
	xrayReady := xrayTun != nil && xrayTun.SupportsUDP() && xrayTun.SupportsIPv6()
	hevReady := packetAdapter != nil && packetAdapter.SupportsUDP() && packetAdapter.SupportsIPv6()
	return xrayReady || hevReady
}

func startHevFallbackLocked() bool {
	if packetAdapter == nil || !packetAdapter.SupportsUDP() || !packetAdapter.SupportsIPv6() {
		return false
	}
	if !packetAdapter.Start(vpnTunFD, vpnSOCKSEndpoint) || !packetAdapter.IsRunning() {
		packetAdapter.Stop()
		return false
	}
	activePacketAdapter = packetAdapter
	activeAdapterName = "HEV (automatic fallback)"
	return true
}

const maxVpnRecoveryAttempts = 3

// recoverStoppedPacketAdapterLocked runs only while vpnMu is held. It gives
// each detected dataplane failure a bounded recovery cycle and never reports
// an adapter active unless its process/native backend is running.
func recoverStoppedPacketAdapterLocked() {
	failed := activePacketAdapter
	if !vpnActive || failed == nil || failed.IsRunning() {
		return
	}
	if vpnRecoveryAttempts >= maxVpnRecoveryAttempts {
		activePacketAdapter = nil
		activeAdapterName = ""
		xrayFallbackReason = "Automatic packet-adapter recovery budget exhausted"
		return
	}
	vpnRecoveryAttempts++

	switch {
	case xrayTun != nil && failed == xrayTun:
		reason := xrayTun.LastError()
		if reason == "" {
			reason = "Xray TUN exited unexpectedly"
		}
		xrayTun.Stop()
		xrayFallbackReason = reason
		if !startHevFallbackLocked() {
			activePacketAdapter = nil
			activeAdapterName = ""
			xrayFallbackReason += "; HEV fallback failed to start"
		}
	case packetAdapter != nil && failed == packetAdapter:
		packetAdapter.Stop()
		reason := "HEV packet adapter stopped unexpectedly"
		if xrayTun != nil && xrayTun.Start(vpnTunFD, vpnSOCKSEndpoint) && xrayTun.IsRunning() {
			activePacketAdapter = xrayTun
			activeAdapterName = "Xray TUN (recovered)"
			xrayFallbackReason = reason + "; recovered with Xray"
			return
		}
		xrayError := ""
		if xrayTun != nil {
			xrayError = xrayTun.LastError()
			xrayTun.Stop()
		}
		if startHevFallbackLocked() {
			xrayFallbackReason = reason + "; Xray retry failed"
			if xrayError != "" {
				xrayFallbackReason += ": " + xrayError
			}
			xrayFallbackReason += "; HEV restarted"
			return
		}
		activePacketAdapter = nil
		activeAdapterName = ""
		xrayFallbackReason = reason + "; Xray retry and HEV restart both failed"
	default:
		failed.Stop()
		activePacketAdapter = nil
		activeAdapterName = ""
		xrayFallbackReason = "Unknown Android packet adapter stopped"
	}
}

func vpnReportLocked() vpnReport {
	proxyMu.Lock()
	running := activeProxy != nil
	proxyMu.Unlock()
	state := vpnReport{
		ProxyRunning:           running,
		PacketAdapterInstalled: packetAdapter != nil || xrayTun != nil,
		UDPReady:               coreSOCKSUDPReady,
		IPv6Ready:              coreIPv6VPNReady,
		Active:                 vpnActive,
		SOCKSUDPImplemented:    true,
		PacketDNSImplemented:   true,
	}
	if xrayTun != nil {
		state.XrayError = xrayTun.LastError()
	}
	switch {
	case !running:
		state.Reason = "Start the existing Go connection core first."
	case !coreSOCKSUDPReady:
		state.Reason = "Go SOCKS UDP and encrypted packet DNS are implemented, but the live Android packet path is not validated."
	case !coreIPv6VPNReady:
		state.Reason = "IPv6 whole-device routing has not been validated."
	case !vpnCandidateAvailable():
		state.Reason = "Neither the Xray TUN adapter nor the HEV fallback supports the required UDP and IPv6 packet path."
	default:
		state.Available = true
		if vpnActive {
			// Recover the packet adapter itself without requiring a manual
			// disconnect/reconnect. Each failure consumes a bounded retry budget.
			recoverStoppedPacketAdapterLocked()
			if activePacketAdapter != nil && activePacketAdapter.IsRunning() {
				state.Active = true
				state.PacketAdapter = activeAdapterName
				state.FallbackReason = xrayFallbackReason
				state.Reason = "Packet adapter is running; per-connection route selection remains owned by Go."
			} else {
				state.Active = false
				state.FallbackReason = xrayFallbackReason
				state.Reason = "The packet adapter stopped and automatic fallback failed; VPN traffic is not verified."
			}
		} else if xrayTun != nil {
			state.Reason = "Packet routing is available. Xray TUN will be attempted first; HEV is the automatic fallback."
		} else {
			state.Reason = "HEV packet routing is available; Android VPN permission is required."
		}
	}
	return state
}

// VpnCapability is a machine-readable live capability check, not a promise
// that a TUN session or network egress exists. Used by Android UI and service.
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
// Go starts Xray's TUN inbound first and falls back to HEV automatically.
// Both adapters forward into the same adaptive Go SOCKS engine.
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
	if activeProxy == nil {
		proxyMu.Unlock()
		return errors.New("Go connection core stopped before TUN attachment")
	}
	endpoint := activeProxy.socks.Addr().String()
	proxyMu.Unlock()

	vpnTunFD, vpnSOCKSEndpoint = fd, endpoint
	vpnRecoveryAttempts = 0
	activePacketAdapter = nil
	activeAdapterName = ""
	xrayFallbackReason = ""
	if xrayTun != nil {
		if xrayTun.Start(fd, endpoint) && xrayTun.IsRunning() {
			activePacketAdapter = xrayTun
			activeAdapterName = "Xray TUN"
		} else {
			vpnRecoveryAttempts++ // Count the initial Xray failure in the bounded recovery budget.
			xrayFallbackReason = xrayTun.LastError()
			if xrayFallbackReason == "" {
				xrayFallbackReason = "Xray TUN did not become healthy"
			}
			xrayTun.Stop()
		}
	}
	if activePacketAdapter == nil {
		if packetAdapter == nil || !packetAdapter.SupportsUDP() || !packetAdapter.SupportsIPv6() ||
			!packetAdapter.Start(fd, endpoint) || !packetAdapter.IsRunning() {
			if packetAdapter != nil {
				packetAdapter.Stop()
			}
			if xrayFallbackReason != "" {
				return fmt.Errorf("Xray TUN failed (%s); HEV fallback did not become healthy", xrayFallbackReason)
			}
			return errors.New("Android packet adapter did not become healthy")
		}
		activePacketAdapter = packetAdapter
		if xrayFallbackReason != "" {
			activeAdapterName = "HEV (automatic fallback)"
		} else {
			activeAdapterName = "HEV"
		}
	}
	vpnActive = true
	return nil
}

// StopVpnTun stops every possible packet process before Android closes its fd
// or the Go SOCKS listener disappears.
func StopVpnTun() {
	vpnMu.Lock()
	defer vpnMu.Unlock()

	// Android may call StopVpnTun from both proxy teardown and VpnService
	// destruction. Once the fd and active adapter have been cleared, repeated
	// calls must be cheap and must not stop a newly attached adapter.
	if !vpnActive && vpnTunFD < 0 && vpnSOCKSEndpoint == "" &&
		activePacketAdapter == nil && activeAdapterName == "" {
		return
	}

	driver := activePacketAdapter
	fallback := packetAdapter
	xray := xrayTun
	vpnActive = false
	activePacketAdapter = nil
	activeAdapterName = ""
	vpnTunFD = -1
	vpnSOCKSEndpoint = ""
	xrayFallbackReason = ""
	vpnRecoveryAttempts = 0

	// Keep the lifecycle lock until every old adapter has stopped. Otherwise a
	// fast reconnect could attach a new TUN while this stale stop still tears
	// down the newly started Xray/HEV process.
	if driver != nil {
		driver.Stop()
	}
	if xray != nil && xray != driver {
		xray.Stop()
	}
	if fallback != nil && fallback != driver {
		fallback.Stop()
	}
}
