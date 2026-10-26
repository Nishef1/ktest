package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
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

func TestParseWindscribeVPNIP(t *testing.T) {
	for _, tc := range []struct{ status, want string }{
		{"Login state: Logged in\r\nConnect state: Connected: Ashburn\r\nVPN IP: 152.233.50.185\r\n", "152.233.50.185"},
		{"vpn ip: 2001:4860:4860::8888", "2001:4860:4860::8888"},
		{"VPN IP: 10.0.0.1", ""},
		{"VPN IP: 127.0.0.1", ""},
		{"VPN IP: 0.0.0.0", ""},
		{"VPN IP: fe80::1", ""},
		{"VPN IP: not an address", ""},
		{"VPN IP: N/A", ""},
		{"Protocol: TCP:443\nConnect state: Connected: Ashburn", ""},
	} {
		if got := parseWindscribeVPNIP(tc.status); got != tc.want {
			t.Errorf("status %q: got VPN IP %q, want %q", tc.status, got, tc.want)
		}
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
		{"pending field prefix", "Login state: Logged in\n*Connect state: Connected: Stockholm - Fika\nProtocol: WireGuard:443\n", windscribeConnecting, true},
		{"interference", "Login state: Logged in\nConnect state: Connected: London [Network interference]\n", windscribeConnecting, true},
		{"connecting", "Login state: Logged in\nConnect state: Connecting\n", windscribeConnecting, true},
		{"reconnecting", "Login state: Logged in\nConnect state: Reconnecting\n", windscribeConnecting, true},
		{"disconnected", "Login state: Logged in\nConnect state: Disconnected\n", windscribeDisconnected, true},
		{"loggedout", "Login state: Not logged in\nConnect state: Disconnected\n", windscribeUnknown, false},
		{"API SSL error with live tunnel", "Login state: Error: SSL error\nConnect state: Connected: London - 1984\nProtocol: TCP:443\nVPN IP: 212.102.63.30\n", windscribeConnected, false},
		{"API error during handshake", "Login state: Error: Network error\nConnect state: Connecting\nProtocol: TCP:443\n", windscribeConnecting, false},
		{"API error during tunnel test", "Login state: Error: SSL error\n*Connect state: Connected: London\nProtocol: TCP:443\nVPN IP: 212.102.63.30\n", windscribeConnecting, false},
		{"API error with local disconnect", "Login state: Error: SSL error\nConnect state: Disconnected\n", windscribeDisconnected, false},
		{"API error without tunnel evidence", "Login state: Error: SSL error\nConnect state: Connected: London\n", windscribeConnecting, false},
		{"API error without public exit", "Login state: Error: SSL error\nConnect state: Connected: London\nProtocol: TCP:443\nVPN IP: 10.0.0.1\n", windscribeConnecting, false},
		{"API error without connection state", "Login state: Error: SSL error\n", windscribeUnknown, false},
		{"explicit logout with stale tunnel", "Login state: Not logged in\nConnect state: Connected: London\nProtocol: TCP:443\nVPN IP: 212.102.63.30\n", windscribeUnknown, false},
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

func TestWindscribeStatusIssueDoesNotEchoCredentials(t *testing.T) {
	message := windscribeStatusIssue("Login state: Not logged in\nToken: NOT_FOR_LOGS\n", windscribeUnknown, false)
	if !strings.Contains(message, "not logged in") || strings.Contains(message, "NOT_FOR_LOGS") {
		t.Fatalf("unsafe login diagnosis: %q", message)
	}
	message = windscribeStatusIssue("No parsable state", windscribeUnknown, false)
	if !strings.Contains(message, "login state") {
		t.Fatalf("missing CLI status diagnosis: %q", message)
	}
	message = windscribeStatusIssue("Login state: Logged in\nConnect state: Unknown", windscribeUnknown, true)
	if !strings.Contains(message, "connection state") {
		t.Fatalf("unrecognized connection treated as trusted: %q", message)
	}
	message = windscribeStatusIssue("Login state: Error: SSL error\n", windscribeUnknown, false)
	if strings.Contains(message, "not logged in") || strings.Contains(message, "SSL error") || strings.Contains(message, "account") {
		t.Fatalf("account API failure misreported as a logout: %q", message)
	}
}

func TestWindscribeCLIStatusGraceExpiresWithoutInventingDisconnection(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name     string
		previous windscribeState
		last     time.Time
		parsed   windscribeState
		login    bool
		err      error
		want     windscribeState
	}{
		{"recent IPC error", windscribeConnected, now.Add(-5 * time.Second), windscribeUnknown, false, errors.New("IPC"), windscribeConnected},
		{"expired IPC error", windscribeConnected, now.Add(-20 * time.Second), windscribeUnknown, false, errors.New("IPC"), windscribeUnknown},
		{"no prior status", windscribeConnected, time.Time{}, windscribeUnknown, false, errors.New("IPC"), windscribeUnknown},
		{"explicit logout", windscribeConnected, now, windscribeUnknown, false, nil, windscribeUnknown},
		{"live tunnel despite API failure", windscribeUnknown, time.Time{}, windscribeConnected, false, nil, windscribeConnected},
		{"handshake despite API failure", windscribeUnknown, time.Time{}, windscribeConnecting, false, nil, windscribeConnecting},
		{"unrecognized CLI status", windscribeConnected, now, windscribeUnknown, true, nil, windscribeUnknown},
		{"actual disconnect", windscribeConnected, now, windscribeDisconnected, true, nil, windscribeDisconnected},
		{"disconnect despite API failure", windscribeUnknown, time.Time{}, windscribeDisconnected, false, nil, windscribeDisconnected},
	} {
		t.Run(test.name, func(t *testing.T) {
			vpnAdapterUp = func() bool { return false }
			defer func() { vpnAdapterUp = func() bool { return len(activeVPNAdapters()) > 0 } }()
			if got := windscribeObservedState(test.previous, test.last, now, test.parsed, test.login, test.err); got != test.want {
				t.Fatalf("got %s, want %s", got, test.want)
			}
		})
	}
}

func TestWindscribeInitialUnknownCLINeverEnablesNestedTunnel(t *testing.T) {
	if !monitorUnknownCLIAllowed(ModeWindscribe) {
		t.Fatal("read-only bridge should keep watching after transient CLI startup failure")
	}
	for _, mode := range []ConnectionMode{ModeWindscribeAether, ModeAether, ModeFast} {
		if monitorUnknownCLIAllowed(mode) {
			t.Fatalf("unknown CLI would authorize unsafe mode %s", mode)
		}
	}
}

func TestWindscribeAutoReconnectWaitsForHTTPBridgeListener(t *testing.T) {
	m := &windscribeMonitor{autoReconnect: true}
	m.mu.Lock()
	readyBefore := m.bridgeReady
	m.mu.Unlock()
	if readyBefore {
		t.Fatal("auto-reconnect was permitted before the HTTP bridge was ready")
	}
	m.markBridgeReady()
	m.mu.Lock()
	readyAfter := m.bridgeReady
	m.mu.Unlock()
	if !readyAfter {
		t.Fatal("ready HTTP bridge did not arm CLI reconnect checks")
	}
}

func TestWindscribeConnectedWithoutCityIsRecognized(t *testing.T) {
	// Desktop CLI emits Connected without a colon when LocationID is invalid;
	// pending tunnel validation and network interference must still fail closed.
	for _, tc := range []struct {
		status string
		want   windscribeState
	}{
		{"Connect state: Connected", windscribeConnected},
		{"*Connect state: Connected", windscribeConnecting},
		{"Connect state: Connected [Network interference]", windscribeConnecting},
	} {
		got, loggedIn := parseWindscribeStatus("Login state: Logged in\n" + tc.status)
		if !loggedIn || got != tc.want {
			t.Fatalf("status %q: got %v, login=%t; want %v", tc.status, got, loggedIn, tc.want)
		}
	}
}

// A Windscribe server ping on :6464 is not a VPN carrier failure. In
// particular, SOCKS5 reply 5 says the endpoint refused TCP CONNECT.
func TestWindscribeLatencyProbeNotCountedAsVPNFailure(t *testing.T) {
	var output bytes.Buffer
	feed := &siteEvents{t: plainTerm(&output), windscribe: true}
	probe := smartproxy.Event{
		Host: "66.90.90.58", Port: "6464",
		Err: "ByeDPI double split: upstream CONNECT failed (reply 5)",
	}
	feed.print(probe)
	feed.print(probe)
	if feed.fail.Load() != 0 || feed.latencyFail.Load() != 2 {
		t.Fatalf("ping failures contaminated VPN response counts: fail=%d latency=%d", feed.fail.Load(), feed.latencyFail.Load())
	}
	if !strings.Contains(output.String(), "LATENCY PROBE FAILED") || strings.Contains(output.String(), "NO REPLY") {
		t.Fatalf("wrong Windscribe ping diagnostic: %q", output.String())
	}
	feed.print(smartproxy.Event{Host: probe.Host, Port: probe.Port, TCPOnly: true})
	if feed.latencyFail.Load() != 2 {
		t.Fatal("SOCKS CONNECT was treated as failed HTTP ping")
	}
	// Other policies must not rewrite arbitrary services on the same port.
	var other bytes.Buffer
	normal := &siteEvents{t: plainTerm(&other)}
	normal.print(probe)
	if normal.fail.Load() != 1 || normal.latencyFail.Load() != 0 {
		t.Fatal("non-Windscribe proxy was incorrectly classified as provider ping")
	}
}

func TestWindscribeExtraAutoReconnectIsOptIn(t *testing.T) {
	options := defaultConnectOptions(t.TempDir())
	if options.windscribeReconnect {
		t.Fatal("ktest must not auto-reconnect on top of Windscribe's own retry manager by default")
	}
}

func TestAPIErrorDisconnectIsDistrustedWhileAVPNAdapterIsUp(t *testing.T) {
	vpnAdapterUp = func() bool { return true }
	defer func() { vpnAdapterUp = func() bool { return len(activeVPNAdapters()) > 0 } }()
	if got := windscribeObservedState(windscribeUnknown, time.Time{}, time.Now(), windscribeDisconnected, false, nil); got != windscribeUnknown {
		t.Fatalf("Disconnected with a live VPN adapter was trusted: %s", got)
	}
}

func TestLimitedAetherBootstrapForBlockedAccountAPI(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		state windscribeState
		err error
		vpnUp, allow bool
	}{
		{"API blocked with no connection field", "Login state: Error: SSL error\nFirewall state: Off", windscribeUnknown, nil, false, true},
		{"API blocked with unknown state", "Login state: Error: Network error\nConnect state: Unknown", windscribeUnknown, nil, false, true},
		{"active VPN adapter", "Login state: Error: SSL error", windscribeUnknown, nil, true, false},
		{"known disconnect uses normal flow", "Login state: Error: SSL error\nConnect state: Disconnected", windscribeDisconnected, nil, false, false},
		{"connected tunnel not overwritten", "Login state: Error: SSL error\nConnect state: Connected: Berlin\nProtocol: TCP:443", windscribeUnknown, nil, false, false},
		{"pending connection", "Login state: Error: SSL error\n*Connect state: Connected: Berlin", windscribeUnknown, nil, false, false},
		{"connecting", "Login state: Error: SSL error\nConnect state: Connecting", windscribeUnknown, nil, false, false},
		{"logout", "Login state: Not logged in\nConnect state: Unknown", windscribeUnknown, nil, false, false},
		{"unrecognized no API error", "Login state: Logged in\nConnect state: Unknown", windscribeUnknown, nil, false, false},
		{"CLI IPC error", "Login state: Error: SSL error", windscribeUnknown, errors.New("IPC"), false, false},
		{"malformed state", "Login state: Error: SSL error\nConnect state: Waiting", windscribeUnknown, nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := windscribeCanBootstrapAPIError(tc.raw, tc.state, tc.err, tc.vpnUp); got != tc.allow {
				t.Fatalf("bootstrap=%v, want=%v", got, tc.allow)
			}
		})
	}
	m := &windscribeMonitor{state: windscribeUnknown, bootstrapOnly: true, autoReconnect: false}
	if !m.BootstrapOnly() || m.Connected() {
		t.Fatal("limited bootstrap was mistaken for authenticated VPN connectivity")
	}
	m.state = windscribeConnected
	if m.BootstrapOnly() {
		t.Fatal("active VPN was granted Aether bootstrap permission")
	}
}
