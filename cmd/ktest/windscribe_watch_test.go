package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

func TestParseWindscribeProtocol(t *testing.T) {
	for _, protocol := range []string{"TCP:443", "WireGuard:443", "Stealth:443", "IKEv2:500", "WStunnel:443"} {
		if got := parseWindscribeProtocol("Login state: Logged in\r\nProtocol: " + protocol + "\r\n"); got != protocol {
			t.Fatalf("got %q, want %q", got, protocol)
		}
	}
	if got := parseWindscribeProtocol("CLI unavailable"); got != "" {
		t.Fatalf("invented protocol: %q", got)
	}
}

func TestWindscribeTCPEstablishmentDoesNotCountAsAnsweredOrFailed(t *testing.T) {
	var output bytes.Buffer
	feed := &siteEvents{t: plainTerm(&output)}
	feed.print(smartproxy.Event{Host: "198.51.100.23", Path: "local ByeDPI", TCPOnly: true})
	if feed.ok.Load() != 0 || feed.fail.Load() != 0 || feed.tcpOnly.Load() != 1 {
		t.Fatalf("unverified TCP counted as an application outcome: ok=%d fail=%d tcp=%d", feed.ok.Load(), feed.fail.Load(), feed.tcpOnly.Load())
	}
}

func TestParseWindscribeStatus(t *testing.T) {
	cases := []struct {
		name, status string
		state        windscribeState
		login        bool
	}{
		{"connected", "Login state: Logged in\nConnect state: Connected: Toronto\nFirewall state: On\n", windscribeConnected, true},
		{"pending", "Login state: Logged in\nConnect state: *Connected: Berlin\n", windscribeConnecting, true},
		{"interference", "Login state: Logged in\nConnect state: Connected: London [Network interference]\n", windscribeConnecting, true},
		{"connecting", "Login state: Logged in\nConnect state: Connecting\n", windscribeConnecting, true},
		{"reconnecting", "Login state: Logged in\nConnect state: Reconnecting\n", windscribeConnecting, true},
		{"disconnected", "Login state: Logged in\nConnect state: Disconnected\n", windscribeDisconnected, true},
		{"loggedout", "Login state: Not logged in\nConnect state: Disconnected\n", windscribeUnknown, false},
		{"ambiguous", "Login state: Logged in\nConnect state: Warming up\n", windscribeUnknown, true},
		{"empty", "", windscribeUnknown, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, login := parseWindscribeStatus(c.status)
			if state != c.state || login != c.login {
				t.Fatalf("parsed state %v, loggedIn %v; expected %v %v", state, login, c.state, c.login)
			}
		})
	}
}

func TestWindscribeStandbyOnlyReleasesOnConfirmedDisconnect(t *testing.T) {
	m := &windscribeMonitor{state: windscribeConnected}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := make(chan bool, 1)
	go func() { result <- m.waitDisconnected(ctx) }()
	m.mu.Lock()
	m.state = windscribeUnknown
	m.mu.Unlock()
	select {
	case <-result:
		t.Fatal("unknown status should never end standby")
	case <-time.After(150 * time.Millisecond):
	}
	m.mu.Lock()
	m.state = windscribeDisconnected
	m.mu.Unlock()
	select {
	case ok := <-result:
		if !ok {
			t.Fatal("standby did not release")
		}
	case <-time.After(time.Second):
		t.Fatal("disconnect not detected")
	}
}

func TestWindscribeStandbyRespectsCancellation(t *testing.T) {
	m := &windscribeMonitor{state: windscribeConnected}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if m.waitDisconnected(ctx) {
		t.Fatal("cancellation not respected")
	}
}

func TestWindscribeOverrideRequiresAbsolutePath(t *testing.T) {
	if _, err := windscribeCLIPath("./windscribe-cli.exe"); err == nil {
		t.Fatal("accepted relative executable")
	}
}
