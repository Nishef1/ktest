package mobilebridge

import "testing"

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
	profiles, err := ladderProfiles("psiphon", "auto")
	if err != nil || len(profiles) != 1 || profiles[0].Method() != "psiphon-cdn" {
		t.Fatalf("Auto must use only the CDN profile: %v, %v", profiles, err)
	}
	only, err := ladderProfiles("psiphon", "psiphon")
	if err != nil || len(only) != 1 || only[0].Method() != "psiphon" {
		t.Fatalf("explicit method = %v, %v", only, err)
	}
	if tor, err := ladderProfiles("tor", "auto"); err != nil || len(tor) != 1 || !tor[0].Has("--tor-only") {
		t.Fatalf("tor = %v, %v", tor, err)
	}
	if _, err := ladderProfiles("tor", "masque-h2"); err == nil {
		t.Fatal("Tor accepted a WARP method")
	}
}

func TestPsiphonRegionOnlyAppliesToPsiphon(t *testing.T) {
	t.Cleanup(func() { _ = SetPsiphonRegion("") })
	_ = SetPsiphonRegion("NL")
	profiles, _ := ladderProfiles("psiphon", "auto")
	if got := withPsiphonRegion(profiles[0]).Value("--psiphon-region"); got != "NL" {
		t.Fatalf("region flag = %q", got)
	}
	tor, _ := ladderProfiles("tor", "auto")
	if withPsiphonRegion(tor[0]).Has("--psiphon-region") {
		t.Fatal("Tor must not get a Psiphon region")
	}
}
