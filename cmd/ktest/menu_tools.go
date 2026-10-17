package main

import (
	"context"
	"runtime"
	"strings"
)

func (t *terminal) chooseCoverage(in *input) bool {
	t.ui.Heading("traffic coverage", "Choose coverage, then select a connection policy (1-4). Windscribe always uses its own app.")
	t.ui.Println("   1  Proxy apps: configure SOCKS5/HTTP in each app; other apps keep their route")
	t.ui.Println("   2  Whole PC (TCP): TUN + chosen policy; Windows Administrator; LAN/helpers exempt")
	t.ui.Note("Whole PC blocks most UDP. It is not a persistent VPN kill switch. Do not combine it with Windscribe.")
	t.ui.Printf("   0  Back\n\n  Coverage > ")
	choice, ok := in.read()
	if !ok {
		return false
	}
	switch choice {
	case "1":
		t.wholePC = false
	case "2":
		if runtime.GOOS != "windows" {
			t.ui.Line(toneWarn, "Whole PC currently supports Windows only")
			return true
		}
		t.wholePC = true
	case "", "0":
		return true
	default:
		t.ui.Line(toneWarn, "Select 1, 2, or 0")
	}
	return true
}

func (t *terminal) diagnoseMenu(base string, in *input) bool {
	t.ui.Heading("diagnostics", "Select the connection you want to diagnose. Probes report sampled stages, not universal access.")
	t.ui.Printf("   1  General network: package, DNS, website TLS/fronting samples\n   2  Windscribe: local bridge prerequisites, CLI state, protocol and conflicts\n   0  Back\n\n  Diagnose > ")
	choice, ok := in.read()
	if !ok {
		return false
	}
	mode := ModeBalanced
	switch choice {
	case "", "1":
	case "2":
		mode = ModeWindscribe
	case "0":
		return true
	default:
		t.ui.Line(toneWarn, "Select 1, 2, or 0")
		return true
	}
	t.ui.Note("Press Enter or Ctrl+C to cancel diagnostics.")
	return t.foreground(func(ctx context.Context) { runDoctorMode(ctx, t.ui, base, false, mode) }, in.lines)
}

func (t *terminal) windscribeTestMenu(base string, in *input) bool {
	t.ui.Heading("Windscribe test", "Compare fixed carrier entries, or verify one HTTPS request through a connected VPN.")
	t.ui.Note("Transport tests do not log in or reconnect. A connected VPN is checked separately with its CLI.")
	t.ui.Printf("  Location or requested TCP IP (Enter = verify connected VPN; 0 = back) > ")
	target, ok := in.read()
	if !ok {
		return false
	}
	if target == "0" {
		return true
	}
	args := []string{"-base", base}
	if target == "" {
		args = append(args, "-verify-vpn")
	} else {
		args = append(args, "-target", target)
		t.ui.Printf("  SNIs (Enter = %s) > ", defaultProbeSNIs)
		names, ok := in.read()
		if !ok {
			return false
		}
		if names != "" {
			args = append(args, "-sni", names)
		}
	}
	t.ui.Note("Press Enter or Ctrl+C to cancel.")
	return t.foreground(func(ctx context.Context) { runWindscribeTestContext(ctx, args, t.ui) }, in.lines)
}

func (t *terminal) cdnScanMenu(in *input) bool {
	t.ui.Heading("CDN tests", "A reachable provider page is different from a CDN route to your own Windscribe origin.")
	t.ui.Printf("  Provider: cloudflare / akamai / google / fastly (Enter = cloudflare; 0 = back) > ")
	provider, ok := in.read()
	if !ok {
		return false
	}
	if provider == "0" {
		return true
	}
	if provider == "" {
		provider = "cloudflare"
	}
	provider = strings.ToLower(provider)
	args := []string{"-provider", provider}
	if provider == "cloudflare" {
		t.ui.Printf("  Your Windscribe CDN hostname (Enter = provider HTTPS test only) > ")
		host, ok := in.read()
		if !ok {
			return false
		}
		if host != "" {
			args = append(args, "-windscribe-cdn", host)
		}
	}
	t.ui.Note("Press Enter or Ctrl+C to cancel. HTTP/TLS success alone never verifies a VPN.")
	return t.foreground(func(ctx context.Context) { runQuickScanContext(ctx, args) }, in.lines)
}
