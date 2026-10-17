package main

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

var aetherMethodChoices = []struct{ name, value string }{
	{"Automatic (measured network order)", "auto"},
	{"MASQUE HTTP/2 (TCP)", "masque-h2"},
	{"MASQUE HTTP/3 (QUIC/UDP)", "masque-h3"},
	{"WireGuard", "wireguard"},
	{"Gool: WireGuard inside MASQUE H2", "gool-h2"},
	{"Gool: WireGuard inside MASQUE H3", "gool-h3"},
	{"Classic WARP-in-WARP (WireGuard inside WireGuard)", "wiw"},
	{"MASQUE-in-MASQUE H2", "mim-h2"},
	{"MASQUE-in-MASQUE H3", "mim-h3"},
	{"Psiphon only", "psiphon"},
	{"Psiphon CDN only", "psiphon-cdn"},
}

func printSavedAether(ctx context.Context, u *term, base string) {
	profiles, err := loadAetherProfiles(base, "cached", "cached", ModeAether)
	if err != nil {
		u.Line(toneWarn, "%v", err)
		return
	}
	printNetworkRecommendations(u, networkSignature(ctx), coreFingerprint(base), profiles)
}

func (t *terminal) chooseAetherMethod(in *input) bool {
	message := ""
	for {
		t.ui.menuViewHeight(32)
		t.ui.Heading("Aether method", "Choice is saved. Only compatible methods are used in each connection mode.")
		if message != "" {
			t.ui.Line(toneWarn, "%s", message)
			message = ""
		}
		for i, c := range aetherMethodChoices {
			selected := ""
			if t.options.aetherMethod == c.value || (t.options.aetherMethod == "" && i == 0) {
				selected = "Selected"
			}
			t.ui.menuOption(strconv.Itoa(i+1), c.name, selected)
		}
		t.ui.menuOption("0", "Back", backHint)
		t.ui.Printf("\n  Method > ")
		answer, ok := in.read()
		if !ok {
			return false
		}
		if answer == "" || isBackChoice(answer) {
			return true
		}
		n, err := strconv.Atoi(answer)
		if err != nil || n < 1 || n > len(aetherMethodChoices) {
			message = fmt.Sprintf("Select 1-%d, or 0", len(aetherMethodChoices))
			continue
		}
		t.options.aetherMethod = aetherMethodChoices[n-1].value
		t.rememberConnect("aether-method", t.options.aetherMethod)
		return true
	}
}

func (t *terminal) aetherMenu(base string, in *input) bool {
	message := ""
	for {
		t.ui.menuView()
		t.ui.Heading("Aether", "Choose automatically from measured routes, or force a transport.")
		if message != "" {
			t.ui.Line(toneWarn, "%s", message)
			message = ""
		}
		method := t.options.aetherMethod
		if method == "" {
			method = "auto"
		}
		t.ui.menuOption("1", "Connect", method)
		t.ui.menuOption("2", "Choose method", "")
		t.ui.menuOption("3", "Compare this network", "3 min · low data")
		t.ui.menuOption("4", "Saved recommendations", "")
		t.ui.menuOption("0", "Back", backHint)
		t.ui.Printf("\n  Aether > ")
		answer, ok := in.read()
		if !ok {
			return false
		}
		if answer == "" || isBackChoice(answer) {
			return true
		}
		switch answer {
		case "1":
			if !t.connectFromMenu(base, in, ModeAether) {
				if in.interrupted {
					in.interrupted = false
					continue
				}
				return false
			}
		case "2":
			if !t.chooseAetherMethod(in) {
				if in.interrupted {
					in.interrupted = false
					continue
				}
				return false
			}
		case "3", "4":
			t.ui.leaveMenu()
			if !t.tool(in, func(ctx context.Context) {
				if answer == "3" {
					runAetherDiagnosis(ctx, t.ui, base, false, 3*time.Minute)
				} else {
					printSavedAether(ctx, t.ui, base)
				}
			}) {
				return false
			}
		default:
			message = "Select 1-4, or 0"
		}
	}
}
