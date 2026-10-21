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

func TestConnectionModes(t *testing.T) {
	r, err := smartproxy.NewAIDomainRules("")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		mode     string
		ai       bool
		ordinary bool
		prefer   bool
	}{
		{"balanced", true, false, false},
		{"fast", true, false, false},
		{"windscribe", true, false, false},
		{"windscribe-aether", true, false, false},
		{"aether", true, false, false}, // ordinary sites: any working exit, see ExitRequired
		{"psiphon", true, true, false},
		{"tor", true, true, false},
	} {
		mode, err := parseConnectionMode(c.mode)
		if err != nil {
			t.Fatal(err)
		}
		cfg := &smartproxy.Config{}
		mode.configure(cfg, r, true)
		ai := cfg.ExitOnly != nil && cfg.ExitOnly("chatgpt.com")
		ordinary := cfg.ExitOnly != nil && cfg.ExitOnly("example.org")
		if ai != c.ai || ordinary != c.ordinary || cfg.PreferVerifiedExit != c.prefer {
			t.Errorf("%s: ai=%v, ordinary=%v, prefer=%v", c.mode, ai, ordinary, cfg.PreferVerifiedExit)
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

func TestFastAIHasNoDirectOrFrontingFallback(t *testing.T) {
	r, _ := smartproxy.NewAIDomainRules("")
	cfg := smartproxy.Config{Upstreams: []smartproxy.Upstream{{Name: "plain"}}}
	ModeFast.configure(&cfg, r, true)
	p, err := smartproxy.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"chatgpt.com", "api.openai.com", "gemini.google.com", "claude.ai", "claude.com"} {
		if _, err := p.DialLocalBypass(context.Background(), host, "443"); err == nil {
			t.Fatalf("local AI dial accepted for %s", host)
		}
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
	rules, _ := smartproxy.NewAIDomainRules("")
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
	_ = rules
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

// The AI policy switch: off routes AI/TikTok like other sites in the mixed and
// Aether modes, but never lifts Psiphon/Tor's exit-only rule.
func TestAIPolicySwitch(t *testing.T) {
	r, err := smartproxy.NewAIDomainRules("")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []ConnectionMode{ModeBalanced, ModeFast, ModeAether, ModeWindscribe} {
		on, off := &smartproxy.Config{}, &smartproxy.Config{}
		mode.configure(on, r, true)
		mode.configure(off, r, false)
		if on.ExitOnly == nil || !on.ExitOnly("chatgpt.com") {
			t.Fatalf("%s: AI policy on does not protect chatgpt.com", mode)
		}
		if off.ExitOnly != nil && (off.ExitOnly("chatgpt.com") || off.ExitOnly("www.tiktok.com")) {
			t.Fatalf("%s: AI policy off still protects AI/TikTok", mode)
		}
	}
	aether := &smartproxy.Config{}
	ModeAether.configure(aether, r, false)
	if aether.ExitRequired == nil || !aether.ExitRequired("chatgpt.com") {
		t.Fatal("Aether lost exit-only carriage with the AI policy off")
	}
	for _, mode := range []ConnectionMode{ModePsiphon, ModeTor} {
		cfg := &smartproxy.Config{}
		mode.configure(cfg, r, false)
		if cfg.ExitOnly == nil || !cfg.ExitOnly("example.org") {
			t.Fatalf("%s: exit-only rule lifted by the AI switch", mode)
		}
	}
}
