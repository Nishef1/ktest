package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/Nishef1/ktest/internal/revive"
)

var serverlessVariants = []struct{ key, variant, label string }{
	{"1", "A", "Fragment A"},
	{"2", "B", "Fragment B"},
	{"3", "OOB", "Out-of-band (OOB)"},
}

func validServerlessVariant(variant string) bool {
	return variant == "A" || variant == "B" || variant == "OOB"
}

// serverlessMenu stores the choice separately from CLI flags and TUN coverage.
func (t *terminal) serverlessMenu(base string, in *input) bool {
	for {
		t.ui.menuView()
		t.ui.Heading("Serverless v65", "PattNG Xray · local ISP route, NOT Psiphon or a foreign VPN")
		t.ui.Note("Your public IP remains the ISP's. Configure apps to use this local proxy.")
		for _, option := range serverlessVariants {
			t.ui.menuOption(option.key, option.label, "HTTP/SOCKS5 · 127.0.0.1:10808")
		}
		t.ui.menuOption("0", "Back", "")
		t.ui.Printf("  Profile > ")
		answer, ok := in.read()
		if !ok {
			return false
		}
		if answer == "" || isBackChoice(answer) {
			return true
		}
		var variant string
		for _, option := range serverlessVariants {
			if answer == option.key {
				variant = option.variant
				break
			}
		}
		if !validServerlessVariant(variant) {
			t.ui.Line(toneWarn, "Select 1, 2, 3 or 0.")
			continue
		}
		t.settings.LastConnection = "serverless"
		t.settings.ServerlessVariant = variant
		t.savePreferences() // A deliberate choice survives an unsuccessful core start.
		return t.startServerless(base, in, variant)
	}
}

// startServerless validates the inspectable portable JSON but executes only
// the embedded, pinned profile. It never changes system routes or proxies.
func (t *terminal) startServerless(base string, in *input, variant string) bool {
	if !validServerlessVariant(variant) {
		t.ui.Line(toneWarn, "Invalid saved Serverless method; select 7 to repair it.")
		return true
	}
	binary := filepath.Join(base, "cores", "xray.exe")
	profile := filepath.Join(base, "profiles", "Serverless-for-Iran.json")
	if _, err := os.Stat(binary); err != nil {
		t.ui.Line(toneWarn, "Bundled Xray is missing; install the Windows portable ZIP.")
		return true
	}
	if err := revive.VerifyPinnedSubscriptionFile(profile); err != nil {
		t.ui.Line(toneWarn, "Serverless profile verification failed: %v. Reinstall the portable ZIP.", err)
		return true
	}
	t.ui.leaveMenu()
	t.ui.Note("Serverless %s · ISP IP · proxy 127.0.0.1:10808. Press Enter to stop.", variant)
	return t.tool(in, func(ctx context.Context) {
		err := revive.RunPinned(ctx, revive.Config{
			XrayBinary: binary, Variant: variant,
			AssetDir: filepath.Join(base, "cores"), Port: revive.DefaultPort, Output: os.Stderr,
		})
		if err != nil && ctx.Err() == nil {
			t.ui.Line(toneWarn, "Serverless %s: %v", variant, err)
		}
	})
}
