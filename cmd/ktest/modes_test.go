package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

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
		{"fast", false, false, false},
		{"windscribe", false, false, false},
		{"vpn", true, true, false},
		{"tor", true, true, false},
	} {
		mode, err := parseConnectionMode(c.mode)
		if err != nil {
			t.Fatal(err)
		}
		cfg := &smartproxy.Config{}
		mode.configure(cfg, r)
		ai := cfg.ExitOnly != nil && cfg.ExitOnly("chatgpt.com")
		ordinary := cfg.ExitOnly != nil && cfg.ExitOnly("example.org")
		if ai != c.ai || ordinary != c.ordinary || cfg.PreferVerifiedExit != c.prefer {
			t.Errorf("%s: ai=%v, ordinary=%v, prefer=%v", c.mode, ai, ordinary, cfg.PreferVerifiedExit)
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
	var b bytes.Buffer
	if code := runInteractive(strings.NewReader("0\n"), &b, t.TempDir()); code != 0 {
		t.Fatal(code)
	}
	for _, name := range []string{"Windscribe", "VPN / exit-only", "Tor only", "Fast / flexible"} {
		if !strings.Contains(b.String(), name) {
			t.Errorf("missing menu item %q", name)
		}
	}
}
