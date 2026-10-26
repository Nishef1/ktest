package mobilebridge

import (
	"testing"

	"github.com/Nishef1/ktest/internal/aether"
)

func TestSetPsiphonRegionValidates(t *testing.T) {
	t.Cleanup(func() { _ = SetPsiphonRegion("") })
	if err := SetPsiphonRegion(" de "); err != nil || currentPsiphonRegion() != "DE" {
		t.Fatalf("region = %q, %v", currentPsiphonRegion(), err)
	}
	for _, bad := range []string{"D", "DEU", "1A", "--"} {
		if SetPsiphonRegion(bad) == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if err := SetPsiphonRegion(""); err != nil || currentPsiphonRegion() != "" {
		t.Fatal("empty region must clear the choice")
	}
}

func TestLadderProfilesAutoIsCDNOnly(t *testing.T) {
	profiles, err := aether.StandaloneProfiles("psiphon", "auto")
	if err != nil || len(profiles) < 2 {
		t.Fatalf("Auto must try several variants: %v, %v", profiles, err)
	}
	if profiles[0].Method() != "psiphon-warp" {
		t.Fatalf("Aether must come first, got %s", profiles[0].Method())
	}
	for _, p := range profiles {
		if m := p.Method(); m != "psiphon-cdn" && m != "psiphon-warp" {
			t.Fatalf("Auto must not use %s", m)
		}
	}
	only, err := aether.StandaloneProfiles("psiphon", "psiphon")
	if err != nil || len(only) != 1 || only[0].Method() != "psiphon" {
		t.Fatalf("explicit method = %v, %v", only, err)
	}
	tor, err := aether.StandaloneProfiles("tor", "auto")
	if err != nil || len(tor) != 1 || !tor[0].Has("--tor-only") {
		t.Fatalf("tor = %v, %v", tor, err)
	}
	if _, err := aether.StandaloneProfiles("tor", "masque-h2"); err == nil {
		t.Fatal("Tor accepted a WARP method")
	}
}

func TestPsiphonWARPPreferenceDefaultIndependent(t *testing.T) {
	SetNativeViaAether(false)
	t.Cleanup(func() { SetNativeViaAether(false) })
	if currentViaAetherFirst() {
		t.Fatal("standalone Psiphon should be first unless WARP-first is explicitly enabled")
	}
	SetNativeViaAether(true)
	if !currentViaAetherFirst() {
		t.Fatal("the user's WARP-first preference was ignored")
	}
}

func TestPsiphonRegionOnlyAppliesToPsiphon(t *testing.T) {
	t.Cleanup(func() { _ = SetPsiphonRegion("") })
	_ = SetPsiphonRegion("NL")
	profiles, _ := aether.StandaloneProfiles("psiphon", "auto")
	if got := aether.WithPsiphonRegion(profiles[0], "NL").Value("--psiphon-region"); got != "NL" {
		t.Fatalf("region flag = %q", got)
	}
	tor, _ := aether.StandaloneProfiles("tor", "auto")
	if aether.WithPsiphonRegion(tor[0], "NL").Has("--psiphon-region") {
		t.Fatal("Tor must not get a Psiphon region")
	}
}

func TestPsiphonAutoSkipsWARPWhenNoKeysExist(t *testing.T) {
	SetNativeViaAether(true)
	t.Cleanup(func() { SetNativeViaAether(false) })
	profiles, err := ladderProfilesForLaunch("psiphon", "auto", t.TempDir())
	if err != nil || len(profiles) == 0 {
		t.Fatalf("no independent Psiphon candidates: %v %v", profiles, err)
	}
	for _, p := range profiles {
		if p.ChainFlag() != "" || p.Method() != "psiphon-cdn" {
			t.Fatalf("auto should not provision WARP before standalone CDN: %v", p.Args)
		}
	}
	// Explicit chain is a deliberate strict choice, not an implicit fallback.
	strict, err := ladderProfilesForLaunch("psiphon", "psiphon-warp", t.TempDir())
	if err != nil || len(strict) == 0 || strict[0].ChainFlag() != "--psiphon" {
		t.Fatalf("explicit WARP first unexpectedly changed protocols: %v %v", strict, err)
	}
	tor, err := ladderProfilesForLaunch("tor", "auto", t.TempDir())
	if err != nil || len(tor) != 1 || !tor[0].Has("--tor-only") {
		t.Fatalf("Tor used WARP preference: %v %v", tor, err)
	}
}
