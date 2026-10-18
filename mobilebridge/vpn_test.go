package mobilebridge

import (
	"encoding/json"
	"strings"
	"testing"
)

type fakePacketAdapter struct {
	starts int
	stops  int
}

func (d *fakePacketAdapter) Start(int, string) bool { d.starts++; return true }
func (d *fakePacketAdapter) Stop()                  { d.stops++ }
func (d *fakePacketAdapter) IsRunning() bool        { return d.starts > d.stops }
func (d *fakePacketAdapter) SupportsUDP() bool      { return true }
func (d *fakePacketAdapter) SupportsIPv6() bool     { return true }

func TestVpnPortRefusesWhenPacketGateIsClosed(t *testing.T) {
	StopVpnTun()
	defer SetAndroidVpnPacketAdapter(nil)
	coreSOCKSUDPReady = false
	defer func() { coreSOCKSUDPReady = true }()
	d := &fakePacketAdapter{}
	SetAndroidVpnPacketAdapter(d)
	if _, err := StartProxy("balanced"); err != nil {
		t.Fatal(err)
	}
	defer StopProxy()
	var report vpnReport
	if err := json.Unmarshal([]byte(VpnCapability()), &report); err != nil {
		t.Fatal(err)
	}
	if report.Available || report.Active || !strings.Contains(report.Reason, "not validated") {
		t.Fatalf("closed gate advertised VPN readiness: %+v", report)
	}
	if err := AttachVpnTun(5); err == nil || d.starts != 0 {
		t.Fatalf("closed gate attached the packet adapter: %v starts=%d", err, d.starts)
	}
}

func TestVpnAttachesAdapterToLiveSOCKSAndStopsWithProxy(t *testing.T) {
	StopVpnTun()
	defer SetAndroidVpnPacketAdapter(nil)
	d := &fakePacketAdapter{}
	SetAndroidVpnPacketAdapter(d)
	if err := AttachVpnTun(5); err == nil {
		t.Fatal("VPN attached without a running proxy")
	}
	if _, err := StartProxy("balanced"); err != nil {
		t.Fatal(err)
	}
	var report vpnReport
	_ = json.Unmarshal([]byte(VpnCapability()), &report)
	if !report.Available {
		t.Fatalf("VPN unavailable with proxy and adapter: %+v", report)
	}
	if err := AttachVpnTun(5); err != nil || d.starts != 1 {
		t.Fatalf("attach failed: %v starts=%d", err, d.starts)
	}
	_ = json.Unmarshal([]byte(VpnCapability()), &report)
	if !report.Active {
		t.Fatalf("attached VPN not reported active: %+v", report)
	}
	StopProxy()
	if d.stops != 1 {
		t.Fatalf("proxy stop left the packet adapter running: stops=%d", d.stops)
	}
}

func TestVpnPortDoesNotOwnAndroidFileDescriptor(t *testing.T) {
	if err := AttachVpnTun(-1); err == nil {
		t.Fatal("accepted invalid Android TUN fd")
	}
}

func TestVpnTunPlanMatchesFullDualStackPolicy(t *testing.T) {
	var p vpnTunPlan
	if err := json.Unmarshal([]byte(VpnTunPlan()), &p); err != nil {
		t.Fatal(err)
	}
	if p.MTU < 1280 || p.IPv4Address == "" || p.IPv6Address == "" ||
		p.IPv4Route != "0.0.0.0" || p.IPv6Route != "::" ||
		p.IPv4DNS == "" || p.IPv6DNS == "" {
		t.Fatalf("incomplete Go-controlled Android TUN plan: %+v", p)
	}
}

func TestStopProxyStopsActivePacketAdapterFirst(t *testing.T) {
	defer func() { StopVpnTun(); SetAndroidVpnPacketAdapter(nil) }()
	backend := &fakePacketAdapter{starts: 1}
	vpnMu.Lock()
	packetAdapter = backend
	vpnActive = true
	vpnMu.Unlock()
	StopProxy()
	if backend.stops != 1 {
		t.Fatalf("disconnect did not stop the attached TUN dataplane: %d", backend.stops)
	}
}
