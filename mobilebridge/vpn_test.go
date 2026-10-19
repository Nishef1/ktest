package mobilebridge

import (
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakePacketAdapter struct {
	starts    int
	stops     int
	failStart bool
}

func (d *fakePacketAdapter) Start(int, string) bool {
	d.starts++
	return !d.failStart
}
func (d *fakePacketAdapter) Stop()              { d.stops++ }
func (d *fakePacketAdapter) IsRunning() bool    { return !d.failStart && d.starts > d.stops }
func (d *fakePacketAdapter) SupportsUDP() bool  { return true }
func (d *fakePacketAdapter) SupportsIPv6() bool { return true }

type fakeXrayTun struct {
	starts    int
	stops     int
	failStart bool
	running   bool
	lastError string
}

func (x *fakeXrayTun) Start(int, string) bool {
	x.starts++
	if x.failStart {
		x.running = false
		if x.lastError == "" {
			x.lastError = "test Xray startup failure"
		}
		return false
	}
	x.running = true
	return true
}
func (x *fakeXrayTun) Stop() {
	x.stops++
	x.running = false
}
func (x *fakeXrayTun) IsRunning() bool   { return x.running }
func (*fakeXrayTun) SupportsUDP() bool   { return true }
func (*fakeXrayTun) SupportsIPv6() bool  { return true }
func (x *fakeXrayTun) LastError() string { return x.lastError }

type blockingStopAdapter struct {
	starts      atomic.Int32
	running     atomic.Bool
	stopStarted chan struct{}
	releaseStop chan struct{}
	stopOnce    sync.Once
	releaseOnce sync.Once
}

func newBlockingStopAdapter() *blockingStopAdapter {
	return &blockingStopAdapter{
		stopStarted: make(chan struct{}),
		releaseStop: make(chan struct{}),
	}
}
func (d *blockingStopAdapter) Start(int, string) bool {
	d.starts.Add(1)
	d.running.Store(true)
	return true
}
func (d *blockingStopAdapter) Stop() {
	d.running.Store(false)
	d.stopOnce.Do(func() { close(d.stopStarted) })
	<-d.releaseStop
}
func (d *blockingStopAdapter) IsRunning() bool   { return d.running.Load() }
func (d *blockingStopAdapter) release() {
	d.releaseOnce.Do(func() { close(d.releaseStop) })
}
func (*blockingStopAdapter) SupportsUDP() bool   { return true }
func (*blockingStopAdapter) SupportsIPv6() bool  { return true }

func resetVpnTestState() {
	StopVpnTun()
	SetAndroidVpnPacketAdapter(nil)
	SetAndroidXrayTunPaths("", "")
	vpnMu.Lock()
	coreSOCKSUDPReady = true
	coreIPv6VPNReady = true
	vpnMu.Unlock()
}

func TestVpnPortRefusesWhenPacketGateIsClosed(t *testing.T) {
	resetVpnTestState()
	defer resetVpnTestState()
	vpnMu.Lock()
	coreSOCKSUDPReady = false
	vpnMu.Unlock()
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

func TestVpnPrefersXrayTUNWhenHealthy(t *testing.T) {
	resetVpnTestState()
	defer resetVpnTestState()
	xray := &fakeXrayTun{}
	hev := &fakePacketAdapter{}
	xrayTun = xray
	SetAndroidVpnPacketAdapter(hev)
	if _, err := StartProxy("balanced"); err != nil {
		t.Fatal(err)
	}
	defer StopProxy()
	if err := AttachVpnTun(5); err != nil {
		t.Fatal(err)
	}
	var report vpnReport
	if err := json.Unmarshal([]byte(VpnCapability()), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Active || report.PacketAdapter != "Xray TUN" || xray.starts != 1 || hev.starts != 0 {
		t.Fatalf("Xray was not selected as the primary packet engine: report=%+v xray=%+v hev=%+v", report, xray, hev)
	}
}

func TestVpnFallsBackToHEVWhenXrayCannotStart(t *testing.T) {
	resetVpnTestState()
	defer resetVpnTestState()
	xray := &fakeXrayTun{failStart: true, lastError: "unsupported test ABI"}
	hev := &fakePacketAdapter{}
	xrayTun = xray
	SetAndroidVpnPacketAdapter(hev)
	if _, err := StartProxy("balanced"); err != nil {
		t.Fatal(err)
	}
	defer StopProxy()
	if err := AttachVpnTun(5); err != nil {
		t.Fatal(err)
	}
	var report vpnReport
	if err := json.Unmarshal([]byte(VpnCapability()), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Active || report.PacketAdapter != "HEV (automatic fallback)" ||
		report.FallbackReason != "unsupported test ABI" || hev.starts != 1 {
		t.Fatalf("HEV fallback was not automatic or observable: report=%+v xray=%+v hev=%+v", report, xray, hev)
	}
}

func TestVpnAutomaticallyFallsBackWhenXrayExits(t *testing.T) {
	resetVpnTestState()
	defer resetVpnTestState()
	xray := &fakeXrayTun{}
	hev := &fakePacketAdapter{}
	xrayTun = xray
	SetAndroidVpnPacketAdapter(hev)
	if _, err := StartProxy("balanced"); err != nil {
		t.Fatal(err)
	}
	defer StopProxy()
	if err := AttachVpnTun(5); err != nil {
		t.Fatal(err)
	}
	xray.running = false
	xray.lastError = "test process exited"
	var report vpnReport
	if err := json.Unmarshal([]byte(VpnCapability()), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Active || report.PacketAdapter != "HEV (automatic fallback)" ||
		report.FallbackReason != "test process exited" || hev.starts != 1 {
		t.Fatalf("Xray exit did not trigger automatic HEV recovery: report=%+v xray=%+v hev=%+v", report, xray, hev)
	}
}


func TestVpnRecoversWithXrayWhenHEVFallbackStops(t *testing.T) {
	resetVpnTestState()
	defer resetVpnTestState()
	xray := &fakeXrayTun{}
	hev := &fakePacketAdapter{}
	xrayTun = xray
	SetAndroidVpnPacketAdapter(hev)
	if _, err := StartProxy("balanced"); err != nil {
		t.Fatal(err)
	}
	defer StopProxy()
	if err := AttachVpnTun(5); err != nil {
		t.Fatal(err)
	}

	// The primary engine exits, so the next service health poll should switch
	// to HEV without requiring the user to disconnect.
	xray.running = false
	xray.lastError = "primary process exited"
	var report vpnReport
	if err := json.Unmarshal([]byte(VpnCapability()), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Active || report.PacketAdapter != "HEV (automatic fallback)" {
		t.Fatalf("Xray failure did not fall back to HEV: %+v", report)
	}

	// If HEV later stops, try Xray again before failing the whole VPN.
	hev.failStart = true
	if err := json.Unmarshal([]byte(VpnCapability()), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Active || report.PacketAdapter != "Xray TUN (recovered)" ||
		!strings.Contains(report.FallbackReason, "recovered with Xray") {
		t.Fatalf("HEV failure did not recover with Xray: %+v", report)
	}
	if xray.starts != 2 {
		t.Fatalf("expected one Xray restart after HEV failure, got %d starts", xray.starts)
	}
}

func TestVpnRecoveryBudgetFailsClosed(t *testing.T) {
	resetVpnTestState()
	defer resetVpnTestState()
	xray := &fakeXrayTun{}
	hev := &fakePacketAdapter{}
	xrayTun = xray
	SetAndroidVpnPacketAdapter(hev)
	if _, err := StartProxy("balanced"); err != nil {
		t.Fatal(err)
	}
	defer StopProxy()
	if err := AttachVpnTun(5); err != nil {
		t.Fatal(err)
	}
	vpnMu.Lock()
	vpnRecoveryAttempts = maxVpnRecoveryAttempts
	vpnMu.Unlock()
	xray.running = false
	var report vpnReport
	if err := json.Unmarshal([]byte(VpnCapability()), &report); err != nil {
		t.Fatal(err)
	}
	if report.Active || report.PacketAdapter != "" ||
		!strings.Contains(report.FallbackReason, "recovery budget exhausted") {
		t.Fatalf("exhausted recovery budget did not fail closed: %+v", report)
	}
	if hev.starts != 0 {
		t.Fatalf("recovery continued after its retry budget was exhausted: HEV starts=%d", hev.starts)
	}
}

func TestVpnAttachesAdapterToLiveSOCKSAndStopsWithProxy(t *testing.T) {
	resetVpnTestState()
	defer resetVpnTestState()
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
	if !report.Active || report.PacketAdapter != "HEV" {
		t.Fatalf("attached VPN not reported active: %+v", report)
	}
	StopProxy()
	if d.stops != 1 {
		t.Fatalf("proxy stop left the packet adapter running: stops=%d", d.stops)
	}
}

func TestStopVpnTunSerializesReattachmentUntilOldAdapterStops(t *testing.T) {
	resetVpnTestState()
	defer resetVpnTestState()
	adapter := newBlockingStopAdapter()
	SetAndroidVpnPacketAdapter(adapter)
	if _, err := StartProxy("balanced"); err != nil {
		t.Fatal(err)
	}
	defer StopProxy()
	defer adapter.release()
	if err := AttachVpnTun(5); err != nil {
		t.Fatal(err)
	}

	stopped := make(chan struct{})
	go func() {
		StopVpnTun()
		close(stopped)
	}()
	select {
	case <-adapter.stopStarted:
	case <-time.After(time.Second):
		t.Fatal("adapter stop did not begin")
	}

	attached := make(chan error, 1)
	go func() { attached <- AttachVpnTun(6) }()
	select {
	case err := <-attached:
		t.Fatalf("reattached while the old adapter was still stopping: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	adapter.release()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("adapter stop did not finish after release")
	}
	select {
	case err := <-attached:
		if err != nil {
			t.Fatalf("reattach after serialized stop failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reattach remained blocked after the old adapter stopped")
	}
	if adapter.starts.Load() != 2 {
		t.Fatalf("expected exactly one fresh adapter start, got %d", adapter.starts.Load())
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
	resetVpnTestState()
	defer resetVpnTestState()
	backend := &fakePacketAdapter{starts: 1}
	SetAndroidVpnPacketAdapter(backend)
	vpnMu.Lock()
	activePacketAdapter = backend
	activeAdapterName = "HEV"
	vpnActive = true
	vpnTunFD = 5
	vpnSOCKSEndpoint = "127.0.0.1:1080"
	vpnMu.Unlock()
	StopProxy()
	if backend.stops != 1 {
		t.Fatalf("disconnect did not stop the attached TUN dataplane: %d", backend.stops)
	}
}
