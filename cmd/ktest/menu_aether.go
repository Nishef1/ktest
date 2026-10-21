package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
	"github.com/Nishef1/ktest/internal/tlsshape"
)

var aetherMethodChoices = func() []struct{ name, value string } {
	var choices []struct{ name, value string }
	for _, method := range aether.Methods() {
		choices = append(choices, struct{ name, value string }{method.Title, method.ID})
	}
	return choices
}()

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
		t.ui.menuOption("5", "F&F and MASQUE SNI", t.tlsChoiceSummary())
		t.ui.menuOption("0", "Back", backHint)
		t.ui.Printf("\n  Aether > ")
		answer, ok := in.read()
		if !ok {
			return false
		}
		if isBackChoice(answer) {
			return true
		}
		switch answer {
		case "", "1":
			if !t.connectFromMenu(base, in, ModeAether) {
				return false
			}
		case "2":
			if !t.chooseAetherMethod(in) {
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
		case "5":
			if !t.aetherTLSMenu(in) {
				return false
			}
		default:
			message = "Select 1-5, or 0"
		}
	}
}

func autoIfEmpty(v string) string {
	if strings.TrimSpace(v) == "" {
		return tlsshape.Auto
	}
	return v
}

func (t *terminal) tlsChoiceSummary() string {
	o := t.options
	if autoIfEmpty(o.aetherFingerprint) == "auto" && autoIfEmpty(o.masqueSNI) == "auto" && autoIfEmpty(o.aetherFragment) == "auto" {
		return "auto"
	}
	return autoIfEmpty(o.aetherFingerprint) + " · " + autoIfEmpty(o.masqueSNI) + " · " + autoIfEmpty(o.aetherFragment)
}

// aetherTLSMenu sets F&F (fingerprint, fragment) and the MASQUE server name.
// Auto, the default, is measured per network; a fixed value is used as given.
func (t *terminal) aetherTLSMenu(in *input) bool {
	message := ""
	for {
		t.ui.menuViewHeight(32)
		t.ui.Heading("F&F and MASQUE SNI", "Auto measures this network and saves the result for 6 hours.")
		if message != "" {
			t.ui.Line(toneWarn, "%s", message)
			message = ""
		}
		t.ui.menuOption("1", "Fingerprint", autoIfEmpty(t.options.aetherFingerprint))
		t.ui.menuOption("2", "MASQUE SNI", autoIfEmpty(t.options.masqueSNI))
		t.ui.menuOption("3", "Fragment", autoIfEmpty(t.options.aetherFragment))
		t.ui.menuOption("4", "Measure this network now", "about 30s · a few KB")
		t.ui.menuOption("5", "All back to auto", "")
		t.ui.menuOption("0", "Back", backHint)
		t.ui.Printf("\n")
		t.ui.Note("Fingerprint: auto keeps Chrome and adds an F&F twin (Patterniha: semi-python, with tlshello-0-len through the exit-node).")
		t.ui.Note("SNI: one name, or names separated by commas to measure among. Fragment: off, or size/delay in bytes/ms such as 8-16/2-10.")
		t.ui.Printf("\n  F&F > ")
		answer, ok := in.read()
		if !ok {
			return false
		}
		if answer == "" || isBackChoice(answer) {
			return true
		}
		var flagName, prompt, current string
		switch answer {
		case "1":
			flagName, current = "aether-fingerprint", t.options.aetherFingerprint
			prompt = "auto / chrome / firefox / semi-python / go"
		case "2":
			flagName, current = "masque-sni", t.options.masqueSNI
			prompt = "auto / name / name1,name2,..."
		case "3":
			flagName, current = "aether-fragment", t.options.aetherFragment
			prompt = "auto / off / size/delay"
		case "4":
			opts, err := aetherTLSOptions(t.options)
			if err != nil {
				message = err.Error()
				continue
			}
			t.ui.leaveMenu()
			if !t.tool(in, func(ctx context.Context) { runTLSCalibration(ctx, t.ui, opts) }) {
				return false
			}
			continue
		case "5":
			t.options.aetherFingerprint, t.options.masqueSNI, t.options.aetherFragment = "auto", "auto", "auto"
			for _, name := range []string{"aether-fingerprint", "masque-sni", "aether-fragment"} {
				t.rememberConnect(name, "auto")
			}
			continue
		default:
			message = "Select 1-5, or 0"
			continue
		}
		t.ui.Printf("  %s (Enter = %s; 0 = back) > ", prompt, autoIfEmpty(current))
		value, ok := in.read()
		if !ok {
			return false
		}
		if value == "" || isBackChoice(value) {
			continue
		}
		next := t.options
		switch flagName {
		case "aether-fingerprint":
			next.aetherFingerprint = value
		case "masque-sni":
			next.masqueSNI = value
		default:
			next.aetherFragment = value
		}
		opts, err := aetherTLSOptions(next)
		if err != nil {
			message = err.Error()
			continue
		}
		next.aetherFingerprint, next.masqueSNI, next.aetherFragment = opts.Fingerprint, opts.SNI, opts.Fragment
		t.options = next
		saved := map[string]string{"aether-fingerprint": opts.Fingerprint, "masque-sni": opts.SNI, "aether-fragment": opts.Fragment}[flagName]
		if t.rememberConnect(flagName, saved) {
			t.notice, t.noticeTone = "Saved: "+flagName+" "+saved+" · applies on next connect", toneInfo
		}
	}
}
