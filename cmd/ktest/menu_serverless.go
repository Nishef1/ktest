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

// serverlessMenu runs an opt-in, direct-ISP local proxy, never a foreign
// exit or system-wide Windows tunnel. Enter stops and cleans up the core.
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
		if variant == "" {
			t.ui.Line(toneWarn, "Select 1, 2, 3 or 0.")
			continue
		}
		binary := filepath.Join(base, "cores", "xray.exe")
		profile := filepath.Join(base, "profiles", "Serverless-for-Iran.json")
		if _, err := os.Stat(binary); err != nil {
			t.ui.Line(toneWarn, "Bundled Xray is missing; install the Windows portable ZIP.")
			continue
		}
		if _, err := os.Stat(profile); err != nil {
			t.ui.Line(toneWarn, "Bundled Serverless subscription is missing; install the Windows portable ZIP.")
			continue
		}
		t.ui.leaveMenu()
		t.ui.Note("Serverless %s · ISP IP · proxy 127.0.0.1:10808. Press Enter to stop.", variant)
		return t.tool(in, func(ctx context.Context) {
			err := revive.Run(ctx, revive.Config{
				XrayBinary: binary, Profile: profile, Variant: variant,
				AssetDir: filepath.Join(base, "cores"), Port: revive.DefaultPort, Output: os.Stderr,
			})
			if err != nil && ctx.Err() == nil {
				t.ui.Line(toneWarn, "Serverless %s: %v", variant, err)
			}
		})
	}
}
