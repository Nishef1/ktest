package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

// Windscribe remains the authority for VPN state, tunnel and firewall.
// ktest watches the official local CLI; it never disables the firewall,
// changes the chosen country or rotates an IP.
type windscribeState uint8

const (
	windscribeUnknown windscribeState = iota
	windscribeConnected
	windscribeDisconnected
	windscribeConnecting
)

func (s windscribeState) String() string {
	switch s {
	case windscribeConnected:
		return "connected"
	case windscribeDisconnected:
		return "disconnected"
	case windscribeConnecting:
		return "connecting"
	default:
		return "unknown"
	}
}

// A '*' prefix means Windscribe's tunnel test is still pending; network
// interference also must not be counted as a safely established VPN.
func parseWindscribeStatus(raw string) (windscribeState, bool) {
	var state windscribeState
	loggedIn := false
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		pendingField := strings.HasPrefix(line, "*")
		line = strings.TrimSpace(strings.TrimPrefix(line, "*"))
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "login state:") {
			status := strings.TrimSpace(strings.TrimPrefix(low, "login state:"))
			loggedIn = status == "logged in"
		}
		if !strings.HasPrefix(low, "connect state:") {
			continue
		}
		value := strings.TrimSpace(line[len("connect state:"):])
		pending := pendingField || strings.HasPrefix(value, "*")
		value = strings.TrimSpace(strings.TrimPrefix(value, "*"))
		lower := strings.ToLower(value)
		switch {
		case strings.HasPrefix(lower, "connected:"):
			if pending || strings.Contains(lower, "[network interference]") {
				state = windscribeConnecting
			} else {
				state = windscribeConnected
			}
		case strings.Contains(lower, "disconnected"):
			state = windscribeDisconnected
		case strings.Contains(lower, "connecting"), strings.Contains(lower, "reconnecting"), strings.Contains(lower, "disconnecting"):
			state = windscribeConnecting
		default:
			state = windscribeUnknown
		}
	}
	if !loggedIn {
		return windscribeUnknown, false
	}
	return state, true
}

func parseWindscribeProtocol(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		field, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && strings.EqualFold(field, "Protocol") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// The CLI's VPN IP is the reported public exit, not the CONNECT target or
// carrier entry. Never substitute an entry address when this field is absent.
func parseWindscribeVPNIP(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		field, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && strings.EqualFold(field, "VPN IP") {
			ip := net.ParseIP(strings.TrimSpace(value))
			if ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
				return ip.String()
			}
		}
	}
	return ""
}

func windscribeCLIPath(override string) (string, error) {
	if override != "" {
		if !filepath.IsAbs(override) {
			return "", errors.New("Windscribe CLI path must be absolute")
		}
		if stat, err := os.Stat(override); err != nil || stat.IsDir() {
			return "", fmt.Errorf("Windscribe CLI not found at %q", override)
		}
		return override, nil
	}
	if runtime.GOOS != "windows" {
		return "", errors.New("Windscribe status monitoring currently supports Windows only")
	}
	roots := []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), `C:\Program Files`}
	for _, root := range roots {
		if root == "" {
			continue
		}
		p := filepath.Join(root, "Windscribe", "windscribe-cli.exe")
		if stat, err := os.Stat(p); err == nil && !stat.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("Windscribe CLI not found (use -windscribe-cli with its absolute path)")
}

type windscribeMonitor struct {
	cli                 string
	t                   *term
	autoReconnect       bool
	mu                  sync.RWMutex
	state               windscribeState
	protocol            string
	vpnIP               string
	connectedOnce       bool
	proxy               *smartproxy.Proxy
	nextReconnect       time.Time
	disconnectedSamples int
}

func (m *windscribeMonitor) State() windscribeState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *windscribeMonitor) Connected() bool { return m != nil && m.State() == windscribeConnected }

// waitDisconnected holds the bootstrap process inactive when ktest launches
// during a live Windscribe VPN session. Only a confirmed disconnection permits
// a fresh bootstrap; unknown states don't indicate an actual disconnect.
func (m *windscribeMonitor) waitDisconnected(ctx context.Context) bool {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		if m.State() == windscribeDisconnected {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-tick.C:
		}
	}
}

func (m *windscribeMonitor) attach(p *smartproxy.Proxy) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.proxy = p
	m.mu.Unlock()
}

func (m *windscribeMonitor) command(ctx context.Context, args ...string) ([]byte, error) {
	callCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	return exec.CommandContext(callCtx, m.cli, args...).CombinedOutput()
}

func (m *windscribeMonitor) refresh(ctx context.Context) {
	out, err := m.command(ctx, "status")
	state, loggedIn := parseWindscribeStatus(string(out))
	if err != nil || !loggedIn {
		// A transient CLI/IPC error is not proof of VPN disconnection.
		// Keep a previously confirmed connected state rather than activating
		// traffic recovery while the VPN may still be running.
		if m.Connected() {
			state = windscribeConnected
		} else {
			state = windscribeUnknown
		}
	}
	m.mu.Lock()
	previous := m.state
	m.state = state
	protocolChanged := false
	previousIP := m.vpnIP
	if err == nil && loggedIn {
		protocol := parseWindscribeProtocol(string(out))
		protocolChanged = protocol != m.protocol
		m.protocol = protocol
		m.vpnIP = ""
		if state == windscribeConnected {
			m.vpnIP = parseWindscribeVPNIP(string(out))
		}
	} else if state != windscribeConnected {
		m.vpnIP = ""
	}
	protocol := m.protocol
	vpnIP := m.vpnIP
	ipChanged := vpnIP != previousIP
	p := m.proxy
	changed := state != previous
	if state == windscribeConnected {
		m.connectedOnce = true
	}
	if state == windscribeDisconnected {
		m.disconnectedSamples++
	} else {
		m.disconnectedSamples = 0
	}
	// Windscribe mode never enables foreign exits. Wait for a stable
	// disconnected state and an available LOCAL packet-shaping path; otherwise the
	// CLI would keep restarting an unreachable VPN every few seconds.
	shouldReconnect := m.autoReconnect && state == windscribeDisconnected &&
		m.disconnectedSamples >= 3 && p != nil && p.HasLocalBypass() &&
		!time.Now().Before(m.nextReconnect)
	if shouldReconnect {
		m.nextReconnect = time.Now().Add(3 * time.Minute)
	}
	m.mu.Unlock()
	if changed {
		switch state {
		case windscribeConnected:
			m.t.Line(toneOK, "Windscribe connected (CLI): standby; leaving VPN routing, IP and firewall to Windscribe")
		case windscribeDisconnected:
			m.t.Line(toneWarn, "Windscribe disconnected (CLI): ktest local anti-DPI TCP bootstrap ready; NO Psiphon/Aether or foreign exit")
		case windscribeConnecting:
			m.t.Note("Windscribe is connecting or validating its tunnel; no duplicate reconnect command")
		default:
			m.t.Note("Windscribe state unavailable; cannot safely auto-reconnect (check CLI/login)")
		}
	}
	if state == windscribeConnected && (changed || ipChanged) {
		if vpnIP != "" {
			m.t.Note("Windscribe VPN IP (CLI): %s; reported exit IP, may differ from requested/entry addresses", vpnIP)
		} else {
			m.t.Note("Windscribe VPN IP (CLI): unavailable; requested/entry addresses are not the VPN exit IP")
		}
	}
	if (changed || protocolChanged) && (state == windscribeConnecting || state == windscribeConnected) &&
		protocol != "" && !strings.HasPrefix(strings.ToLower(protocol), "tcp:") {
		m.t.Note("Windscribe protocol %s: this VPN tunnel is not carried by ktest's HTTP bootstrap; use OpenVPN TCP to test local anti-DPI", protocol)
	}
	if shouldReconnect {
		m.t.Note("Local anti-DPI TCP proxy ready; requesting last Windscribe location (cooldown 3min, no IP-changing ktest exits)")
		_, e := m.command(ctx, "connect", "-n")
		if e != nil && ctx.Err() == nil {
			m.t.Note("Windscribe reconnect command failed: %v", e)
		}
	}
}

func startWindscribeMonitor(ctx context.Context, o connectOptions, t *term) *windscribeMonitor {
	if o.mode != ModeWindscribe {
		return nil
	}
	path, err := windscribeCLIPath(o.windscribeCLI)
	if err != nil {
		t.Note("Windscribe monitor unavailable: %v; recovery remains manual until CLI is available", err)
		return nil
	}
	m := &windscribeMonitor{cli: path, t: t, autoReconnect: o.windscribeReconnect}
	m.refresh(ctx) // initial state before external tunnel scanning
	if m.State() == windscribeUnknown {
		t.Note("Windscribe CLI status not trusted yet; running bootstrap in manual fallback mode (no automatic reconnect)")
		return nil
	}
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.refresh(ctx)
			}
		}
	}()
	return m
}
