package mobilebridge

import (
    "encoding/json"
    "strings"
    "testing"
)

type fakePacketAdapter struct {
    starts int
    stops int
}
func (d *fakePacketAdapter) Start(int, string) bool { d.starts++; return true }
func (d *fakePacketAdapter) Stop() { d.stops++ }
func (d *fakePacketAdapter) IsRunning() bool { return d.starts > d.stops }
func (d *fakePacketAdapter) SupportsUDP() bool { return true }
func (d *fakePacketAdapter) SupportsIPv6() bool { return true }

func TestVpnPortRefusesToRouteTCPOnlyGoProxy(t *testing.T) {
    StopVpnTun()
    defer SetAndroidVpnPacketAdapter(nil)
    d := &fakePacketAdapter{}
    SetAndroidVpnPacketAdapter(d)
    if _, err := StartProxy("balanced"); err != nil {
        t.Fatal(err)
    }
    defer StopProxy()
    var report vpnReport
    if err := json.Unmarshal([]byte(VpnCapability()), &report); err != nil { t.Fatal(err) }
    if report.Available || report.Active || !report.ProxyRunning ||
        !strings.Contains(report.Reason, "TCP CONNECT only") {
        t.Fatalf("a TCP-only listener must not be advertised as VPN-ready: %+v", report)
    }
    if err := AttachVpnTun(5); err == nil {
        t.Fatal("native backend was allowed to attach an unsupported Go transport")
    }
    if d.starts != 0 {
        t.Fatalf("native driver was called despite missing UDP support: %d", d.starts)
    }
    StopVpnTun()
    if d.stops != 0 { t.Fatal("stop was called despite no active native session") }
}

func TestVpnPortDoesNotOwnAndroidFileDescriptor(t *testing.T) {
    if err := AttachVpnTun(-1); err == nil {
        t.Fatal("accepted invalid Android TUN fd")
    }
}

func TestVpnTunPlanMatchesFullDualStackPolicy(t *testing.T) {
    var p vpnTunPlan
    if err := json.Unmarshal([]byte(VpnTunPlan()), &p); err != nil { t.Fatal(err) }
    if p.MTU < 1280 || p.IPv4Address == "" || p.IPv6Address == "" ||
        p.IPv4Route != "0.0.0.0" || p.IPv6Route != "::" ||
        p.IPv4DNS == "" || p.IPv6DNS == "" {
        t.Fatalf("incomplete Go-controlled Android TUN plan: %+v", p)
    }
}
