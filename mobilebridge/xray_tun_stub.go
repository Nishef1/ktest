//go:build !android

package mobilebridge

// The desktop CLI has its own TUN adapters. This stub keeps the shared Go
// package and gomobile source checks portable; Android registers the real
// Xray implementation only from VpnService.
type xrayTunPacketAdapter struct {
	lastError string
}

func newXrayTunPacketAdapter(_, _ string) androidXrayTun {
	return &xrayTunPacketAdapter{lastError: "Xray TUN packet adapter is Android-only"}
}

func (a *xrayTunPacketAdapter) Start(int, string) bool {
	a.lastError = "Xray TUN packet adapter is Android-only"
	return false
}
func (*xrayTunPacketAdapter) Stop()               {}
func (*xrayTunPacketAdapter) IsRunning() bool     { return false }
func (*xrayTunPacketAdapter) SupportsUDP() bool   { return true }
func (*xrayTunPacketAdapter) SupportsIPv6() bool  { return true }
func (a *xrayTunPacketAdapter) LastError() string { return a.lastError }
