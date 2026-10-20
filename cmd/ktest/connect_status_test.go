package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

func TestConnectionStatusStates(t *testing.T) {
	p, err := smartproxy.New(smartproxy.Config{ExitOnly: func(string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	start := time.Now()
	s := &connectionStatus{t: plainTerm(&out), mode: ModeAether, proxy: p, socks: "127.0.0.1:10800", stop: "Press Enter",
		tunWant: true, tunOn: func() bool { return false }, started: start, since: start}

	if v := s.view(start.Add(20 * time.Second)); v.key != "connecting" || v.tone != toneWarn ||
		!strings.Contains(strings.Join(v.lines, "\n"), "starts automatically once connected") {
		t.Fatalf("searching = %+v", v)
	}
	if v := s.view(start.Add(notConnectedAfter)); v.key != "failing" || v.title != "NOT CONNECTED" {
		t.Fatalf("stalled = %+v", v)
	}
	s.render(start)
	if err := p.Add(smartproxy.Upstream{Name: "Exit: test", Exit: true, AIEligible: true}); err != nil {
		t.Fatal(err)
	}
	s.tunOn = func() bool { return true }
	s.render(start.Add(30 * time.Second))
	v := s.view(start.Add(90 * time.Second))
	if v.key != "connected" || v.tone != toneOK || !strings.Contains(v.lines[0], "1m 00s") || !strings.Contains(v.lines[1], "Whole PC") {
		t.Fatalf("connected = %+v", v)
	}
	// Plain output: one box per state, and the change is logged.
	if got := out.String(); strings.Count(got, "CONNECTING") != 1 || strings.Count(got, "CONNECTED") != 1 || !strings.Contains(got, "Connected\n") {
		t.Fatalf("transcript:\n%s", got)
	}

	fast := &connectionStatus{t: plainTerm(&bytes.Buffer{}), mode: ModeFast, proxy: p, socks: "127.0.0.1:10800", started: start, since: start}
	if v := fast.view(start); v.key != "connected" || !strings.Contains(strings.Join(v.lines, "\n"), "Foreign exit for AI/TikTok: ready") {
		t.Fatalf("fast = %+v", v)
	}
}

func TestWindscribeAetherStatusSaysWhenToWaitAndWhenToConnect(t *testing.T) {
	p, err := smartproxy.New(smartproxy.Config{ExitOnly: func(string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	start := time.Now()
	monitor := &windscribeMonitor{state: windscribeDisconnected}
	s := &connectionStatus{t: plainTerm(&out), mode: ModeWindscribeAether, proxy: p, windscribe: monitor,
		http: "127.0.0.1:10801", stop: "Press Enter", started: start, since: start}
	check := func(key, action string) {
		t.Helper()
		v := s.view(start)
		if v.key != key || !strings.Contains(strings.Join(v.lines, "\n"), action) {
			t.Fatalf("expected %s / %s, got %+v", key, action, v)
		}
		s.render(start)
	}
	check("carrier-searching", "Wait; do not start Windscribe yet")
	s.render(start.Add(time.Second))
	if err := p.Add(smartproxy.Upstream{Name: "Exit: carrier", Exit: true, AIEligible: false}); err != nil {
		t.Fatal(err)
	}
	// A working local-country carrier is sufficient for Windscribe; a
	// foreign/AI-eligible WARP exit must not be an additional waiting gate.
	check("carrier-ready", "Connect Windscribe now")
	if strings.Contains(out.String(), "WINDSCRIBE CONNECTED") {
		t.Fatalf("carrier readiness was presented as VPN authentication: %s", out.String())
	}
	monitor.state = windscribeConnecting
	check("vpn-connecting", "do not reconnect")
	monitor.state = windscribeConnected
	check("vpn-connected", "Keep ktest and Aether running")
	p.Remove("Exit: carrier")
	check("vpn-connected", "Keep ktest and Aether running")
	monitor.state = windscribeDisconnected
	check("carrier-searching", "Wait; do not start Windscribe yet")
	if strings.Count(out.String(), "WINDSCRIBE CONNECTED (CLI)") != 1 {
		t.Fatalf("unchanged VPN state was repeatedly announced: %s", out.String())
	}
	t.Log("State transition transcript:\n" + out.String())
}

func TestWindscribeAetherUnknownCLIRequiresCheckingAppBeforeConnecting(t *testing.T) {
	p, err := smartproxy.New(smartproxy.Config{ExitOnly: func(string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Add(smartproxy.Upstream{Name: "Exit: carrier", Exit: true}); err != nil {
		t.Fatal(err)
	}
	s := &connectionStatus{t: plainTerm(&bytes.Buffer{}), mode: ModeWindscribeAether, proxy: p, started: time.Now()}
	v := s.view(time.Now())
	text := strings.Join(v.lines, "\n")
	if v.key != "carrier-ready-unknown" || !strings.Contains(text, "Check Windscribe") || strings.Contains(text, "Connect Windscribe now") {
		t.Fatalf("unknown CLI status led to an unconditional connect instruction: %+v", v)
	}
}
