package main

import (
	"context"
	"time"
)

func (t *terminal) windscribeMenu(base string, in *input) bool {
	message := ""
	for {
		t.ui.menuView()
		t.ui.Heading("Windscribe", "Windscribe owns the VPN account, authentication, final exit and system coverage.")
		if message != "" {
			t.ui.Line(toneWarn, "%s", message)
			message = ""
		}
		t.ui.menuOption("1", "Local anti-DPI bridge", "No Aether / WARP / Psiphon")
		t.ui.menuOption("2", "Windscribe through Aether", "WARP carries OpenVPN TCP; keep Aether running")
		t.ui.menuOption("3", "Zapret2 bridge (Windows experimental)", "Detect the node automatically when you click Connect in Windscribe")
		t.ui.menuOption("4", "Diagnostics and tests", "")
		t.ui.menuOption("0", "Back", backHint)
		t.ui.Printf("\n  Windscribe > ")
		answer, ok := in.read()
		if !ok {
			return false
		}
		if isBackChoice(answer) {
			return true
		}
		switch answer {
		case "1", "2":
			mode := ModeWindscribe
			if answer == "2" {
				mode = ModeWindscribeAether
			}
			// Option 1 always means the ordinary local bridge, even when a
			// packet strategy was previously saved from the CLI.
			previous := t.options.ws.zapret
			t.options.ws.zapret = ""
			alive := t.connectFromMenu(base, in, mode)
			t.options.ws.zapret = previous
			if !alive {
				return false
			}
		case "3":
			if !t.windscribeZapretMenu(base, in) {
				return false
			}
		case "4":
			if !t.windscribeToolsMenu(base, in) {
				return false
			}
		default:
			message = "Select 1-4, or 0"
		}
	}
}

func (t *terminal) windscribeToolsMenu(base string, in *input) bool {
	message := ""
	for {
		t.ui.menuViewHeight(34)
		t.ui.Heading("Windscribe tests", "Transport readiness, VPN authentication and actual data are separate checks.")
		if message != "" {
			t.ui.Line(toneWarn, "%s", message)
			message = ""
		}
		for _, row := range []struct{ key, name, detail string }{
			{"1", "Prerequisites / CLI / firewall", "Read-only"},
			{"2", "Compare WStunnel entries and SNIs", "TLS + WebSocket 101"},
			{"3", "Compare Stealth entries and SNIs", "TLS only"},
			{"4", "Compare both transports", "Fixed Windscribe node"},
			{"5", "Run local bridge / observe VPN", "Real client owns OpenVPN authentication"},
			{"6", "Compare Aether carrier methods", "3 min · neutral requests"},
			{"7", "Run Windscribe through Aether", "OpenVPN TCP; explicit extra tunnel"},
			{"8", "Verify connected VPN data", "System HTTPS + optional app-reported VPN IP"},
			{"9", "Test own CDN route", "Requires your configured hostname"},
			{"10", "Zapret2 manual A/B comparison", "Fixed entry/SNI; transport test only"},
		} {
			t.ui.menuOption(row.key, row.name, row.detail)
		}
		t.ui.menuOption("0", "Back", backHint)
		t.ui.Printf("\n  Windscribe test > ")
		answer, ok := in.read()
		if !ok {
			return false
		}
		if isBackChoice(answer) {
			return true
		}
		alive := true
		switch answer {
		case "10":
			alive = t.windscribeZapretTestMenu(base, in)
		case "2", "3", "4":
			transport := map[string]string{"2": "wstunnel", "3": "stealth", "4": "both"}[answer]
			t.settings.Tools.WindscribeTransport = transport
			t.savePreferences()
			alive = t.windscribeTestMenu(base, in)
		case "5", "7":
			mode := ModeWindscribe
			if answer == "7" {
				mode = ModeWindscribeAether
			}
			alive = t.connectFromMenu(base, in, mode)
		case "9":
			alive = t.cdnScanMenu(in)
		case "8":
			t.ui.Printf("  VPN IP shown in Windscribe app (Enter = measure only; 0 = back) > ")
			expected, ok := in.read()
			if !ok {
				return false
			}
			if isBackChoice(expected) {
				continue
			}
			args := []string{"-base", base, "-verify-vpn"}
			if expected != "" {
				args = append(args, "-expected-vpn-ip", expected)
			}
			t.ui.leaveMenu()
			alive = t.tool(in, func(ctx context.Context) {
				runWindscribeTestContext(ctx, args, t.ui)
			})
		case "1", "6":
			t.ui.leaveMenu()
			alive = t.tool(in, func(ctx context.Context) {
				if answer == "1" {
					runDoctorMode(ctx, t.ui, base, false, ModeWindscribe)
				} else {
					runAetherDiagnosis(ctx, t.ui, base, false, 3*time.Minute)
				}
			})
		default:
			message = "Select 1-10, or 0"
		}
		if !alive {
			return false
		}
	}
}
