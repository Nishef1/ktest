package main

import (
	"context"
	"runtime"
	"strconv"
	"strings"
	"time"
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
		t.ui.Note("Most UDP is blocked, except in Aether (UDP rides WARP). TUN is not a persistent VPN kill switch.")
		t.ui.Note("Changes are saved automatically.")
		t.ui.menuOption("0", "Back", backHint)
		t.ui.Printf("\n  Coverage > ")
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

// isYes is the one confirmation word: y (or yes) in any case.
func isYes(answer string) bool {
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true
	}
	return false
}

// backHint labels the Back row of a list menu: Enter on a list with no stated
// default always goes back, never starts something.
const backHint = ""

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
		t.ui.Heading("diagnostics", "General network or Windscribe.")
		if message != "" {
			t.ui.Line(toneWarn, "%s", message)
			message = ""
		}
		previous := t.settings.Tools.DiagnosisMode
		if previous != "2" && previous != "3" && previous != "4" && previous != "5" {
			previous = "1"
		}
		t.ui.Printf("   1  General network\n   2  Windscribe prerequisites\n   3  Aether comparison (3 min; low data)\n   4  Aether comparison + small transfer samples\n   5  Saved recommendations for this network\n   0  Back\n\n  Diagnose (Enter = %s) > ", previous)
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
		case "3", "4", "5":
		default:
			message = "Select 1-5, or 0"
			continue
		}
		t.settings.Tools.DiagnosisMode = choice
		t.savePreferences()
		t.ui.leaveMenu()
		t.ui.Note("Press Enter to cancel diagnostics and return here.")
		if !t.tool(in, func(ctx context.Context) {
			switch choice {
			case "3", "4":
				runAetherDiagnosis(ctx, t.ui, base, choice == "4", 3*time.Minute)
			case "5":
				printSavedAether(ctx, t.ui, base)
			default:
				runDoctorMode(ctx, t.ui, base, false, mode)
			}
		}) {
			return false
		}
	}
}

func (t *terminal) windscribeTestMenu(base string, in *input) bool {
	message := ""
	for {
		t.ui.menuView()
		t.ui.Heading("Windscribe test", "Compare carrier entries or verify a connected VPN.")
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
		transport := t.settings.Tools.WindscribeTransport
		if transport != "stealth" && transport != "wstunnel" {
			transport = "both"
		}
		args := []string{"-base", base, "-transport", transport}
		if target == "" {
			args = append(args, "-verify-vpn")
		} else {
			args = append(args, "-target", target)
			previousSNIs := t.settings.Tools.WindscribeSNIs
			if previousSNIs == "" {
				previousSNIs = defaultProbeSNIs
			}
			t.ui.Printf("  SNIs (Enter = %s; 0 = back) > ", previousSNIs)
			names, ok := in.read()
			if !ok {
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
		t.ui.Note("Press Enter to cancel and return here.")
		best := ""
		alive, finished := t.run(func(ctx context.Context) { runWindscribeTestContext(ctx, args, t.ui, func(sni string) { best = sni }) }, in.enter())
		if !alive {
			return false
		}
		if best == "" && finished && !t.holdResult(in) {
			return false
		}
		if best != "" {
			for {
				t.ui.Printf("  Use suggested SNI %s first for the local Windscribe bridge? y = apply / Enter = keep settings / 0 = back > ", best)
				answer, ok := in.read()
				if !ok {
					return false
				}
				if isYes(answer) {
					t.options.ws.sni = best + "," + defaultWindscribeSNIs
					t.rememberConnect("windscribe-wstunnel-sni", t.options.ws.sni)
					break
				}
				if answer == "" || isBackChoice(answer) {
					break
				}
				t.ui.Line(toneWarn, "Enter y to apply, or Enter / 0 to keep settings")
			}
		}
	}
}

func (t *terminal) cdnScanMenu(in *input) bool {
	message := ""
	for {
		t.ui.menuView()
		t.ui.Heading("CDN tests", "Provider HTTPS or your own Windscribe CDN route.")
		if message != "" {
			t.ui.Line(toneWarn, "%s", message)
			message = ""
		}
		previous := t.settings.Tools.ScanProvider
		if previous == "" {
			previous = "cloudflare"
		}
		t.ui.Printf("  Provider: cloudflare / akamai / google / fastly / meta / cloudfront / gcore (Enter = %s; 0 = back) > ", previous)
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
		case "cloudflare", "akamai", "google", "fastly", "meta", "cloudfront", "gcore":
		default:
			message = "Select cloudflare, akamai, google, fastly, meta, cloudfront, gcore, or 0"
			continue
		}
		args := []string{"-provider", provider}
		if provider == "cloudflare" {
			if previous := t.settings.Tools.ScanCDN; previous != "" {
				t.ui.Printf("  CDN hostname (Enter = %s; - = no CDN; 0 = back) > ", previous)
			} else {
				t.ui.Printf("  CDN hostname (Enter = provider test; 0 = back) > ")
			}
			host, ok := in.read()
			if !ok {
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
		t.ui.Note("Press Enter to cancel and return here.")
		if !t.tool(in, func(ctx context.Context) { runQuickScanContext(ctx, args) }) {
			return false
		}
	}
}
