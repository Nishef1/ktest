package aether

import (
	"strings"
	"testing"
	"time"
)

func TestFastNeverLaunchesForeignHelperBackends(t *testing.T) {
	profiles, err := ParseProfiles(DefaultProfiles, "ech", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"--tor-only", "--tor", "--psiphon", "--psiphon-reverse", "--tor-reverse", "--upstream=socks5://127.0.0.1:9000"} {
		profiles = append(profiles, Profile{Label: flag, Args: []string{"--masque", flag}})
	}
	fast := ProfilesForMode(profiles, "fast")
	if len(fast) == 0 {
		t.Fatal("Fast lost native Aether transports")
	}
	for _, p := range fast {
		if p.Psiphon() || p.Has("--tor-only") || p.Has("--tor") || p.Has("--psiphon") || p.Has("--psiphon-reverse") || p.Has("--tor-reverse") || p.Has("--upstream") {
			t.Fatalf("Fast launched a prohibited helper: %v", p.Args)
		}
	}
	if len(ProfilesForMode(profiles, "balanced")) != len(profiles) {
		t.Fatal("Balanced lost fallback methods")
	}
}

func TestIndependentProfileOrderingPreservesWinnerAndBackendCoverage(t *testing.T) {
	profiles := []Profile{
		{Label: "warp", Args: []string{"--masque", "--h2"}},
		{Label: "variant", Args: []string{"--masque", "--h3"}},
		{Label: "psiphon", Args: []string{"--psiphon-only"}},
		{Label: "cdn", Args: []string{"--psiphon-only", "--psiphon-mode", "cdn"}},
		{Label: "tor", Args: []string{"--tor-only"}},
	}
	ordered := IndependentProfilesFirst(profiles)
	for i, label := range []string{"warp", "cdn", "tor", "psiphon", "variant"} {
		if ordered[i].Label != label {
			t.Fatalf("candidate %d = %s, want %s", i, ordered[i].Label, label)
		}
	}
	fast := IndependentProfilesFirst(ProfilesForMode(profiles, "fast"))
	if len(fast) != 2 || fast[0].Label != "warp" || fast[1].Label != "variant" {
		t.Fatal("recovery ordering changed Fast's permitted inventory")
	}
	profiles[0], profiles[4] = profiles[4], profiles[0]
	if ordered = IndependentProfilesFirst(profiles); ordered[0].Label != "tor" || ordered[2].Label != "variant" {
		t.Fatal("a preferred independent backend did not retain its first attempt")
	}
}

func TestCachedPsiphonDoesNotBuryCDNRetryBehindWarpVariants(t *testing.T) {
	profiles := []Profile{{Label: "cached", Args: []string{"--psiphon-only"}}}
	for range 12 {
		profiles = append(profiles, Profile{Label: "warp", Args: []string{"--masque", "--h2"}})
	}
	profiles = append(profiles,
		Profile{Label: "cdn", Args: []string{"--psiphon-only", "--psiphon-mode", "cdn"}},
		Profile{Label: "tor", Args: []string{"--tor-only"}})
	ordered := IndependentProfilesFirst(profiles)
	if ordered[0].Label != "cached" || ordered[3].Label != "cdn" || len(ordered) != len(profiles) {
		t.Fatal("a failed cached Psiphon path can starve its independent CDN retry")
	}
}

func TestGoolEnrollmentUsesOnlyOuterMasqueForBothFlagForms(t *testing.T) {
	for _, args := range [][]string{
		{"--gool", "--h2", "--gool-peer", "192.0.2.1:2408"},
		{"--protocol=gool", "--h2", "--gool-peer=192.0.2.1:2408"},
	} {
		inner := Profile{Label: "inner", Args: args}
		outer := GoolOuterProfile(inner)
		if outer.Method() != "masque-h2" || outer.Has("--gool-peer") {
			t.Fatalf("inner enrollment would recursively require its missing inner identity: %v", outer.Args)
		}
		if !strings.Contains(strings.Join(inner.Args, " "), "gool") {
			t.Fatal("outer bootstrap mutated the saved inner profile")
		}
	}
}

func TestNativeStartupDeadlinePreservesEqualsFormAndCannotOverflow(t *testing.T) {
	if got := AttemptTimeout(Profile{Args: []string{"--psiphon-only"}}); got < 200*time.Second {
		t.Fatalf("Psiphon is canceled before its native 180-second readiness deadline and verification margin: %s", got)
	}
	for _, args := range [][]string{{"--startup-secs", "100"}, {"--startup-secs=100"}} {
		if got := AttemptTimeout(Profile{Args: args}); got != 120*time.Second {
			t.Fatalf("core can be canceled before its configured startup deadline: %v", got)
		}
	}
	for _, value := range []string{"-1", "invalid", "999999999999999999999999999"} {
		if got := AttemptTimeout(Profile{Args: []string{"--startup-secs=" + value}}); got != 65*time.Second {
			t.Fatalf("invalid native startup created an unsafe timeout: %v", got)
		}
	}
}

func TestIdentityRequirementsKeepStandaloneAndNestedKeysSeparate(t *testing.T) {
	for _, flag := range []string{"--psiphon-only", "--tor-only"} {
		if len(IdentityRequirements(Profile{Args: []string{flag}})) != 0 {
			t.Fatalf("%s unexpectedly requires WARP registration", flag)
		}
	}
	for _, args := range [][]string{{"--gool"}, {"--gool-classic"}, {"--mim"}} {
		required := IdentityRequirements(Profile{Args: args})
		if len(required) != 2 || required[0].Name == required[1].Name {
			t.Fatalf("nested identity would replace the primary: %+v", required)
		}
	}
}

func TestAetherFlagsAdaptToInstalledCoreWithoutLosingUnknownOptions(t *testing.T) {
	oldHelp := "  --masque  protocol\n  --h2  http2\n  --enroll-address <ip>  registration\n  --api-fragment  register\n  --no-fragment  disable\n  --fragment  split\n"
	newHelp := "  --masque  protocol\n  --h2  http2\n  --api-address <ip>  registration\n  --fragment  split\n"
	modern := Profile{Label: "H2", Args: []string{"--masque", "--h2", "--api-address=1.2.3.4", "--fragment"}}
	old := SupportedProfiles([]Profile{modern}, oldHelp)
	if len(old) != 1 || !old[0].Has("--enroll-address") || old[0].Has("--api-address") {
		t.Fatalf("new profile cannot run on the pinned legacy core: %+v", old)
	}
	legacy := Profile{Label: "H2", Args: []string{"--masque", "--h2", "--enroll-address=1.2.3.4", "--api-fragment", "--no-fragment"}}
	modernized := SupportedProfiles([]Profile{legacy}, newHelp)
	if len(modernized) != 1 || !modernized[0].Has("--api-address") || modernized[0].Has("--enroll-address") ||
		!modernized[0].Has("--fragment") || modernized[0].Has("--no-fragment") || modernized[0].Has("--api-fragment") {
		t.Fatalf("legacy profile cannot run on the PattNG-aligned core: %+v", modernized)
	}
	if got := SupportedProfiles([]Profile{{Label: "invalid", Args: []string{"--masque", "--fictional-transport"}}}, newHelp); len(got) != 0 {
		t.Fatalf("unknown transport silently accepted: %+v", got)
	}
}

func TestRenamedAetherAPIOptionsPreserveStableProfileIDs(t *testing.T) {
	old := Profile{Label: "h2", Args: []string{"--masque", "--enroll-address", "1.2.3.4", "--api-fragment", "--ech", "one"}}
	modern := Profile{Label: "h2", Args: []string{"--masque", "--api-address", "5.6.7.8", "--fragment", "--ech", "two"}}
	if old.ID() != modern.ID() {
		t.Fatalf("equivalent profiles lost identity across CLI upgrade: %s != %s", old.ID(), modern.ID())
	}
}

func TestModernAetherPreservesLocalCarrierWithoutRemovedNoFragmentFlag(t *testing.T) {
	profiles := WithLocalCarriers([]Profile{{Label: "H2", Args: []string{"--masque", "--h2"}}})
	if len(profiles) != 2 || !profiles[1].Has("--no-fragment") {
		t.Fatalf("test fixture no longer covers legacy carrier flags: %+v", profiles)
	}
	newHelp := "  --masque  protocol\n  --h2  transport\n  --upstream <url>  proxy\n  --fragment  TLS\n"
	accepted := SupportedProfiles(profiles, newHelp)
	if len(accepted) != 2 || accepted[1].Has("--no-fragment") ||
		!accepted[1].LocalCarrier() {
		t.Fatalf("new core lost its local carrier or received unsupported flags: %+v", accepted)
	}
}

func TestExitModeCannotSilentlySwitchToAnotherNativeBackend(t *testing.T) {
	profiles := []Profile{
		{Label: "WARP", Args: []string{"--masque", "--h2"}},
		{Label: "Psiphon", Args: []string{"--psiphon-only"}},
		{Label: "Psiphon CDN", Args: []string{"--psiphon-only", "--psiphon-mode", "cdn"}},
		{Label: "Tor", Args: []string{"--tor-only"}},
		{Label: "nested disguise", Args: []string{"--masque", "--psiphon-reverse"}},
		{Label: "external carrier", Args: []string{"--masque", "--upstream", "socks5://127.0.0.1:10001"}},
		{Label: "local carrier", Args: []string{"--masque", "--h2", "--upstream", LocalCarrierURL}},
	}
	for _, tc := range []struct {
		mode  string
		wants []string
	}{
		{"aether", []string{"WARP", "local carrier"}},
		{"fast", []string{"WARP", "local carrier"}},
		{"windscribe-aether", []string{"WARP"}},
		{"psiphon", []string{"Psiphon", "Psiphon CDN"}},
		{"tor", []string{"Tor"}},
		{"balanced", []string{"WARP", "Psiphon", "Psiphon CDN", "Tor", "nested disguise", "external carrier", "local carrier"}},
		{"windscribe", nil},
	} {
		got := ProfilesForMode(profiles, tc.mode)
		if len(got) != len(tc.wants) {
			t.Fatalf("%s: wrong backend inventory: %+v, want %v", tc.mode, got, tc.wants)
		}
		for i, want := range tc.wants {
			if got[i].Label != want {
				t.Fatalf("%s: unexpected backend %q at %d, want %q", tc.mode, got[i].Label, i, want)
			}
		}
	}
}

func TestPsiphonOnlyCannotSmuggleTorOrWarpFlags(t *testing.T) {
	ps := []Profile{
		{Label: "plain", Args: []string{"--psiphon-only"}},
		{Label: "mixed tor", Args: []string{"--psiphon-only", "--tor"}},
		{Label: "mixed warp", Args: []string{"--psiphon-only", "--wg"}},
	}
	got := ProfilesForMode(ps, "psiphon")
	if len(got) != 1 || got[0].Label != "plain" {
		t.Fatalf("Psiphon-only included mixed backends: %+v", got)
	}
}
