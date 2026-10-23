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
	if err != nil || len(tor) != 2 || tor[0].Method() != "tor-warp" || !tor[1].Has("--tor-only") {
		t.Fatalf("tor = %v, %v", tor, err)
	}
	if _, err := aether.StandaloneProfiles("tor", "masque-h2"); err == nil {
		t.Fatal("Tor accepted a WARP method")
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
