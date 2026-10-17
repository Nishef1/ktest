package main

import (
	"context"
	"runtime"
	"strconv"
	"strings"
)

func (t *terminal) chooseCoverage(in *input) bool {
	t.ui.Heading("traffic coverage", "Choose coverage, then select a connection policy (1-4, 6). Windscribe always uses its own app.")
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
		t.options.tun = false
	case "2":
		if runtime.GOOS != "windows" {
			t.ui.Line(toneWarn, "Whole PC currently supports Windows only")
			return true
		}
		t.options.tun = true
	case "", "0":
		return true
	default:
		t.ui.Line(toneWarn, "Select 1, 2, or 0")
		return true
	}
	t.rememberConnect("tun", strconv.FormatBool(t.options.tun))
	return true
}

func (t *terminal) diagnoseMenu(base string, in *input) bool {
	t.ui.Heading("diagnostics", "Select the connection you want to diagnose. Probes report sampled stages, not universal access.")
	previous := t.settings.Tools.DiagnosisMode
	if previous != "2" {
		previous = "1"
	}
	t.ui.Printf("   1  General network: package, DNS, website TLS/fronting samples\n   2  Windscribe: local bridge prerequisites, CLI state, protocol and conflicts\n   0  Back\n\n  Diagnose (Enter = %s) > ", previous)
	choice, ok := in.read()
	if !ok {
		return false
	}
	mode := ModeBalanced
	if choice == "" {
		choice = previous
	}
	switch choice {
	case "1":
	case "2":
		mode = ModeWindscribe
	case "0":
		return true
	default:
		t.ui.Line(toneWarn, "Select 1, 2, or 0")
		return true
	}
	t.settings.Tools.DiagnosisMode = choice
	t.savePreferences()
	t.ui.Note("Press Enter or Ctrl+C to cancel diagnostics.")
	return t.foreground(func(ctx context.Context) { runDoctorMode(ctx, t.ui, base, false, mode) }, in.lines)
}

func (t *terminal) windscribeTestMenu(base string, in *input) bool {
	t.ui.Heading("Windscribe test", "Compare fixed carrier entries, or verify one HTTPS request through a connected VPN.")
	t.ui.Note("Transport tests do not log in or reconnect. A connected VPN is checked separately with its CLI.")
	previous := t.settings.Tools.WindscribeTarget
	if previous == "" {
		t.ui.Printf("  Location or requested TCP IP (Enter = verify connected VPN; 0 = back) > ")
	} else {
		t.ui.Printf("  Location or requested TCP IP (Enter = %s; - = verify connected VPN; 0 = back) > ", previous)
	}
	target, ok := in.read()
	if !ok {
		return false
	}
	if target == "0" {
		return true
	}
	if target == "" {
		target = previous
	} else if target == "-" {
		target = ""
	}
	args := []string{"-base", base}
	if target == "" {
		args = append(args, "-verify-vpn")
	} else {
		args = append(args, "-target", target)
		previousSNIs := t.settings.Tools.WindscribeSNIs
		if previousSNIs == "" {
			previousSNIs = defaultProbeSNIs
		}
		t.ui.Printf("  SNIs (Enter = %s) > ", previousSNIs)
		names, ok := in.read()
		if !ok {
			return false
		}
		if names == "" {
			names = previousSNIs
		}
		if _, err := parseProbeSNIs(names); err != nil {
			t.ui.Line(toneWarn, "%v", err)
			return true
		}
		args = append(args, "-sni", names)
		t.settings.Tools.WindscribeSNIs = names
	}
	t.settings.Tools.WindscribeTarget = target
	t.savePreferences()
	t.ui.Note("Press Enter or Ctrl+C to cancel.")
	return t.foreground(func(ctx context.Context) { runWindscribeTestContext(ctx, args, t.ui) }, in.lines)
}

func (t *terminal) cdnScanMenu(in *input) bool {
	t.ui.Heading("CDN tests", "A reachable provider page is different from a CDN route to your own Windscribe origin.")
	previous := t.settings.Tools.ScanProvider
	if previous == "" {
		previous = "cloudflare"
	}
	t.ui.Printf("  Provider: cloudflare / akamai / google / fastly (Enter = %s; 0 = back) > ", previous)
	provider, ok := in.read()
	if !ok {
		return false
	}
	if provider == "0" {
		return true
	}
	if provider == "" {
		provider = previous
	}
	provider = strings.ToLower(provider)
	switch provider {
	case "cloudflare", "akamai", "google", "fastly":
	default:
		t.ui.Line(toneWarn, "Select cloudflare, akamai, google, fastly, or 0")
		return true
	}
	args := []string{"-provider", provider}
	if provider == "cloudflare" {
		if previous := t.settings.Tools.ScanCDN; previous != "" {
			t.ui.Printf("  Your Windscribe CDN hostname (Enter = %s; - = provider HTTPS test only) > ", previous)
		} else {
			t.ui.Printf("  Your Windscribe CDN hostname (Enter = provider HTTPS test only) > ")
		}
		host, ok := in.read()
		if !ok {
			return false
		}
		if host == "" {
			host = t.settings.Tools.ScanCDN
		} else if host == "-" {
			host = ""
		}
		if host != "" {
			if !validHostname(host) {
				t.ui.Line(toneWarn, "CDN hostname must be a hostname without a URL scheme or path")
				return true
			}
			args = append(args, "-windscribe-cdn", host)
		}
		t.settings.Tools.ScanCDN = host
	}
	t.settings.Tools.ScanProvider = provider
	t.savePreferences()
	t.ui.Note("Press Enter or Ctrl+C to cancel. HTTP/TLS success alone never verifies a VPN.")
	return t.foreground(func(ctx context.Context) { runQuickScanContext(ctx, args) }, in.lines)
}
