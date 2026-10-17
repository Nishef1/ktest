package main

import (
	"context"
	"runtime"
	"strconv"
	"strings"
)

func (t *terminal) chooseCoverage(in *input) bool {
	message := ""
	for {
		t.ui.menuView()
		t.ui.Heading("traffic coverage", "Applies to methods 1-4 and 6. Windscribe uses its own VPN.")
		if message != "" {
			t.ui.Line(toneWarn, "%s", message)
			message = ""
		}
		proxy, tun := "   1  Proxy     Only apps configured to use ktest", "   2  TUN       System TCP traffic"
		if t.options.tun {
			tun = t.ui.Cyan(" >") + tun[2:] + t.ui.Cyan(" · Selected")
		} else {
			proxy = t.ui.Cyan(" >") + proxy[2:] + t.ui.Cyan(" · Selected")
		}
		t.ui.Println(proxy)
		t.ui.Println(tun)
		t.ui.Printf("\n")
		t.ui.Note("TUN needs Windows Administrator; LAN and helper processes are exempt.")
		t.ui.Note("Most UDP is blocked. TUN is not a persistent VPN kill switch.")
		t.ui.Note("Changes are saved automatically.")
		t.ui.Printf("   0  Back\n\n  Coverage > ")
		choice, ok := in.read()
		if !ok {
			return false
		}
		if choice == "" || isBackChoice(choice) {
			return true
		}
		switch choice {
		case "1":
			t.options.tun = false
		case "2":
			if runtime.GOOS != "windows" {
				message = "TUN currently supports Windows only"
				continue
			}
			t.options.tun = true
		default:
			message = "Select 1, 2, or 0"
			continue
		}
		if t.rememberConnect("tun", strconv.FormatBool(t.options.tun)) {
			mode := "Proxy"
			if t.options.tun {
				mode = "TUN"
			}
			t.notice, t.noticeTone = "Saved: "+mode+" · Enter to connect", toneInfo
		}
		return true
	}
}

// Back is available at every submenu prompt; Enter keeps its stated default.
func isBackChoice(choice string) bool {
	switch strings.ToLower(strings.TrimSpace(choice)) {
	case "0", "b", "back":
		return true
	}
	return false
}

func (t *terminal) diagnoseMenu(base string, in *input) bool {
	message := ""
	for {
		t.ui.menuView()
		t.ui.Heading("diagnostics", "General network or Windscribe. Ctrl+C goes back.")
		if message != "" {
			t.ui.Line(toneWarn, "%s", message)
			message = ""
		}
		previous := t.settings.Tools.DiagnosisMode
		if previous != "2" {
			previous = "1"
		}
		t.ui.Printf("   1  General network\n   2  Windscribe\n   0  Back\n\n  Diagnose (Enter = %s) > ", previous)
		choice, ok := in.read()
		if !ok {
			return false
		}
		if isBackChoice(choice) {
			return true
		}
		if choice == "" {
			choice = previous
		}
		mode := ModeBalanced
		switch choice {
		case "1":
		case "2":
			mode = ModeWindscribe
		default:
			message = "Select 1, 2, or 0"
			continue
		}
		t.settings.Tools.DiagnosisMode = choice
		t.savePreferences()
		t.ui.leaveMenu()
		t.ui.Note("Press Enter or Ctrl+C to cancel diagnostics and return here.")
		if !t.foreground(func(ctx context.Context) { runDoctorMode(ctx, t.ui, base, false, mode) }, in.lines) {
			return false
		}
	}
}

func (t *terminal) windscribeTestMenu(base string, in *input) bool {
	message := ""
	for {
		t.ui.menuView()
		t.ui.Heading("Windscribe test", "Compare carrier entries or verify a connected VPN. Ctrl+C goes back.")
		if message != "" {
			t.ui.Line(toneWarn, "%s", message)
			message = ""
		}
		previous := t.settings.Tools.WindscribeTarget
		if previous == "" {
			t.ui.Printf("  Location or TCP IP (Enter = verify connected VPN; 0 = back) > ")
		} else {
			t.ui.Printf("  Location or TCP IP (Enter = %s; - = verify connected VPN; 0 = back) > ", previous)
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
			t.ui.Printf("  SNIs (Enter = %s; 0 or Ctrl+C = back) > ", previousSNIs)
			names, ok := in.read()
			if !ok {
				if in.interrupted {
					in.interrupted = false
					continue
				}
				return false
			}
			if isBackChoice(names) {
				continue
			}
			if names == "" {
				names = previousSNIs
			}
			if _, err := parseProbeSNIs(names); err != nil {
				message = err.Error()
				continue
			}
			args = append(args, "-sni", names)
			t.settings.Tools.WindscribeSNIs = names
		}
		t.settings.Tools.WindscribeTarget = target
		t.savePreferences()
		t.ui.leaveMenu()
		t.ui.Note("Press Enter or Ctrl+C to cancel and return here.")
		if !t.foreground(func(ctx context.Context) { runWindscribeTestContext(ctx, args, t.ui) }, in.lines) {
			return false
		}
	}
}

func (t *terminal) cdnScanMenu(in *input) bool {
	message := ""
	for {
		t.ui.menuView()
		t.ui.Heading("CDN tests", "Provider HTTPS or your own Windscribe CDN route. Ctrl+C goes back.")
		if message != "" {
			t.ui.Line(toneWarn, "%s", message)
			message = ""
		}
		previous := t.settings.Tools.ScanProvider
		if previous == "" {
			previous = "cloudflare"
		}
		t.ui.Printf("  Provider: cloudflare / akamai / google / fastly (Enter = %s; 0 = back) > ", previous)
		provider, ok := in.read()
		if !ok {
			return false
		}
		if isBackChoice(provider) {
			return true
		}
		if provider == "" {
			provider = previous
		}
		provider = strings.ToLower(provider)
		switch provider {
		case "cloudflare", "akamai", "google", "fastly":
		default:
			message = "Select cloudflare, akamai, google, fastly, or 0"
			continue
		}
		args := []string{"-provider", provider}
		if provider == "cloudflare" {
			if previous := t.settings.Tools.ScanCDN; previous != "" {
				t.ui.Printf("  CDN hostname (Enter = %s; - = no CDN; 0 or Ctrl+C = back) > ", previous)
			} else {
				t.ui.Printf("  CDN hostname (Enter = provider test; 0 or Ctrl+C = back) > ")
			}
			host, ok := in.read()
			if !ok {
				if in.interrupted {
					in.interrupted = false
					continue
				}
				return false
			}
			if isBackChoice(host) {
				continue
			}
			if host == "" {
				host = t.settings.Tools.ScanCDN
			} else if host == "-" {
				host = ""
			}
			if host != "" {
				if !validHostname(host) {
					message = "CDN hostname must be a bare hostname without a URL scheme or path"
					continue
				}
				args = append(args, "-windscribe-cdn", host)
			}
			t.settings.Tools.ScanCDN = host
		}
		t.settings.Tools.ScanProvider = provider
		t.savePreferences()
		t.ui.leaveMenu()
		t.ui.Note("Press Enter or Ctrl+C to cancel and return here.")
		if !t.foreground(func(ctx context.Context) { runQuickScanContext(ctx, args) }, in.lines) {
			return false
		}
	}
}
