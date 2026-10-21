package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

func TestPsiphonModeRejectsUnidentifiedExternalExit(t *testing.T) {
	if code := runConnect([]string{"-mode", "psiphon", "-exit-socks", "127.0.0.1:19000"}); code != 2 {
		t.Fatalf("external SOCKS allowed in Psiphon mode: %d", code)
	}
	o := defaultConnectOptions(t.TempDir())
	o.mode, o.exitSocks = ModePsiphon, "127.0.0.1:19000"
	var output bytes.Buffer
	if code := connectSession(context.Background(), o, nil, newTerm(&output)); code != 2 {
		t.Fatalf("session bypassed Psiphon-only restriction: %d", code)
	}
}

// No site is singled out: AI and TikTok route like the rest in every mode.
// Only Psiphon and Tor keep every site on their exit.
func TestConnectionModes(t *testing.T) {
	for _, c := range []struct {
		mode     string
		exitOnly bool
	}{
		{"balanced", false}, {"fast", false}, {"windscribe", false}, {"windscribe-aether", false},
		{"aether", false}, // every site rides an exit of any location, see ExitRequired
		{"psiphon", true}, {"tor", true},
	} {
		mode, err := parseConnectionMode(c.mode)
		if err != nil {
			t.Fatal(err)
		}
		cfg := &smartproxy.Config{}
		mode.configure(cfg)
		for _, host := range []string{"chatgpt.com", "www.tiktok.com", "example.org"} {
			if got := cfg.ExitOnly != nil && cfg.ExitOnly(host); got != c.exitOnly {
				t.Errorf("%s: ExitOnly(%s)=%v", c.mode, host, got)
			}
		}
		if cfg.PreferVerifiedExit {
			t.Errorf("%s: PreferVerifiedExit", c.mode)
		}
		if required := cfg.ExitRequired != nil && cfg.ExitRequired("example.org"); required != (mode == ModeAether) {
			t.Errorf("%s: ExitRequired=%v; only Aether sends every site through an exit of any location", c.mode, required)
		}
		if cfg.RejectExits != (mode == ModeWindscribe) {
			t.Errorf("%s: RejectExits=%v; Windscribe must reject all foreign egress", c.mode, cfg.RejectExits)
		}
		if cfg.LocalOnly != (mode == ModeWindscribe) {
			t.Errorf("%s: LocalOnly=%v; Windscribe cannot allow plain or unknown proxy routes", c.mode, cfg.LocalOnly)
		}
	}
	if _, err := parseConnectionMode("unknown"); err == nil {
		t.Fatal("unrecognized mode accepted")
	}
}

func TestFastRejectsExplicitForeignHelpersBeforeStartingCores(t *testing.T) {
	for _, method := range []string{"auto", "psiphon", "psiphon-cdn"} {
		o := defaultConnectOptions(t.TempDir())
		o.mode = ModeFast
		o.aetherMethod = method
		if (validateConnectOptions(o) == nil) != (method == "auto") {
			t.Fatalf("Fast accepted incompatible method %s", method)
		}
	}
	o := defaultConnectOptions(t.TempDir())
	o.mode = ModeFast
	o.exitSocks = "127.0.0.1:19001"
	if validateConnectOptions(o) == nil {
		t.Fatal("Fast accepted an unidentified core")
	}
}

func TestMixedModesIncludeXrayAlongsideLocalRoutes(t *testing.T) {
	if !ModeFast.allowsXray() || !ModeBalanced.allowsXray() || !ModeWindscribe.allowsXray() {
		t.Fatal("Fast, Balanced and local-only Windscribe must retain their supported Xray routes")
	}
}

func TestStrictProxyCanStartWithoutVerifiedExit(t *testing.T) {
	p, err := smartproxy.New(smartproxy.Config{ExitOnly: func(string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Stats()) != 0 {
		t.Fatal("unexpected exits")
	}
	if err := p.Add(smartproxy.Upstream{Name: "unverified", Addr: "127.0.0.1:19399", Exit: true, AIEligible: false}); err != nil {
		t.Fatal(err)
	}
	if len(p.Winners()) != 0 {
		t.Fatal("unverified exit recorded")
	}
}

func TestModesVisibleInMainMenu(t *testing.T) {
	output := menuOutput(t, "0\n")
	for _, name := range []string{"Balanced", "Fast", "Aether", "Aether to Psiphon", "Aether to Tor", "Windscribe"} {
		if !strings.Contains(output, name) {
			t.Errorf("missing menu item %q", name)
		}
	}
}

func TestWindscribeModesRequireHTTPProxy(t *testing.T) {
	for _, mode := range []ConnectionMode{ModeWindscribe, ModeWindscribeAether} {
		o := defaultConnectOptions(t.TempDir())
		o.mode, o.tun, o.noHTTP = mode, false, true
		if err := validateConnectOptions(o); err == nil || !strings.Contains(err.Error(), "HTTP CONNECT") {
			t.Fatalf("%s accepted unusable -no-http configuration: %v", mode, err)
		}
	}
}
