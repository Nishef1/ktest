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
