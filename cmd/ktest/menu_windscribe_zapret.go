package main

import (
	"context"
	"runtime"
	"strings"

	"github.com/Nishef1/ktest/internal/systemtun"
)

func (t *terminal) windscribeZapretMenu(base string, in *input) bool {
	t.ui.menuView()
	t.ui.Heading("Windscribe / Zapret2 bridge (experimental)", "Click Connect in Windscribe; its requested node is detected automatically.")
	t.ui.Note("Use Windscribe OpenVPN TCP/443 with HTTP Proxy Settings pointing to 127.0.0.1:10801.")
	t.ui.Note("Zapret2 temporarily affects other processes using the same entry IP:443 during each outer handshake.")
	if err := checkWindscribeZapret(base); err != nil {
		t.ui.Line(toneWarn, "%v", err)
		t.ui.Printf("\n  Press Enter or 0 to return > ")
		_, ok := in.read()
		return ok
	}
	o := t.menuConnectOptions(base, ModeWindscribe)
	if !o.ws.packetEnabled() {
		o.ws.zapret = "fake"
	}
	o.ws.direct = true
	o.ws.serverIP, o.ws.cdnHost, o.ws.cdnSNI, o.ws.cdnEdges = "", "", "", ""
	t.options.mode = ModeWindscribe
	t.rememberConnect("mode", string(ModeWindscribe))
	t.ui.leaveMenu()
	return t.connectWithOptions(in, o)
}

// The fixed-entry comparison remains available separately under diagnostics.
func (t *terminal) windscribeZapretTestMenu(base string, in *input) bool {
	t.ui.menuViewHeight(33)
	t.ui.Heading("Windscribe / Zapret2 (experimental)", "Windows packet-layer A/B test; does NOT connect Windscribe VPN.")
	t.ui.Note("A baseline WStunnel probe is compared with the same target and SNI under Zapret2.")
	t.ui.Note("Requires Windscribe CLI: Disconnected, Administrator, no ktest TUN.")
	t.ui.Note("WinDivert affects other processes connecting to the selected IP:443 during each test.")
	if runtime.GOOS != "windows" || !systemtun.IsAdmin() {
		t.ui.Line(toneWarn, "This test needs Windows Terminal explicitly launched as Administrator; no UAC elevation is requested.")
		t.ui.Printf("\n  Press Enter or 0 to return > ")
		_, ok := in.read()
		return ok
	}

	previous := strings.TrimSpace(t.settings.Tools.WindscribeTarget)
	if previous != "" {
		t.ui.Printf("\n  Windscribe location or TCP IP (Enter = %s; 0 = back) > ", previous)
	} else {
		t.ui.Printf("\n  Windscribe location or TCP IP (required; 0 = back) > ")
	}
	target, ok := in.read()
	if !ok {
		return false
	}
	if isBackChoice(target) {
		return true
	}
	if target == "" {
		target = previous
	}
	if target == "" || len(target) > 160 {
		t.ui.Line(toneWarn, "Choose one location or provider-advertised TCP IP (up to 160 characters).")
		return true
	}

	const defaultSNI = "www.speedtest.net"
	t.ui.Printf("  Single TLS SNI (Enter = %s; 0 = back) > ", defaultSNI)
	sni, ok := in.read()
	if !ok {
		return false
	}
	if isBackChoice(sni) {
		return true
	}
	if sni == "" {
		sni = defaultSNI
	}
	names, err := parseProbeSNIs(sni)
	if err != nil || len(names) != 1 || names[0] == "" {
		t.ui.Line(toneWarn, "Use exactly one valid hostname as SNI (not a list or 'none').")
		return true
	}
	sni = names[0]

	t.ui.menuOption("1", "Fake TLS", "Zapret2 fake TLS packet")
	t.ui.menuOption("2", "Multisplit", "Zapret2 packet-level split")
	t.ui.menuOption("3", "Combined", "Fake TLS + sequence-overlapped multisplit")
	t.ui.menuOption("0", "Cancel", backHint)
	t.ui.Printf("\n  Zapret2 strategy > ")
	choice, ok := in.read()
	if !ok {
		return false
	}
	if isBackChoice(choice) || choice == "" {
		return true
	}
	strategy := map[string]string{"1": "fake", "2": "split", "3": "combo"}[choice]
	if strategy == "" {
		t.ui.Line(toneWarn, "Select strategy 1, 2 or 3.")
		return true
	}

	t.ui.Line(toneWarn, "This changes the Windows packet path TEMPORARILY for the chosen IP:443, not just ktest.")
	t.ui.Note("Neither a successful TLS handshake nor WebSocket 101 verifies OpenVPN authentication or VPN access.")
	t.ui.Printf("  Run 2 serial baseline/Zapret2 pairs for %s with SNI %s and %s? Type y to confirm / 0 to cancel > ", target, sni, strategy)
	confirm, ok := in.read()
	if !ok {
		return false
	}
	if !isYes(confirm) {
		return true
	}
	t.settings.Tools.WindscribeTarget = target
	t.savePreferences()
	args := []string{
		"-base", base, "-target", target,
		"-transport", "wstunnel", "-sni", sni,
		"-rounds", "2", "-timeout", "4s", "-zapret", strategy,
	}
	t.ui.leaveMenu()
	t.ui.Note("Experiment only. Press Enter or Ctrl+C to cancel; the owned winws2 process must be stopped.")
	return t.tool(in, func(ctx context.Context) {
		runWindscribeTestContext(ctx, args, t.ui)
	})
}
