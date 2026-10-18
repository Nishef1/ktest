package mobilebridge

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAetherCatalogPreservesAndroidModeAndIdentityBoundaries(t *testing.T) {
	for _, mode := range []string{"psiphon", "windscribe-aether", "tor"} {
		raw, err := AetherProfileCatalog(mode, "auto")
		if err != nil {
			t.Fatal(err)
		}
		var report struct {
			Profiles []struct {
				Method     string `json:"method"`
				Identities []struct {
					Protocol string `json:"protocol"`
				} `json:"identities"`
			} `json:"profiles"`
		}
		if err := json.Unmarshal([]byte(raw), &report); err != nil {
			t.Fatal(err)
		}
		if len(report.Profiles) == 0 {
			t.Fatal("shared transport inventory missing")
		}
		for _, profile := range report.Profiles {
			switch mode {
			case "psiphon":
				if profile.Method != "psiphon" && profile.Method != "psiphon-cdn" {
					t.Fatal("non-Psiphon profile escaped mode filter")
				}
			case "tor":
				if profile.Method != "tor" || len(profile.Identities) != 0 {
					t.Fatal("Tor inherited WARP identity or method")
				}
			case "windscribe-aether":
				if profile.Method == "psiphon" || profile.Method == "psiphon-cdn" || profile.Method == "tor" {
					t.Fatal("Windscribe WARP carrier inherited Tor/Psiphon")
				}
			}
		}
	}
	for _, tc := range [][2]string{{"windscribe", "auto"}, {"unknown", "auto"}, {"psiphon", "wireguard"}, {"tor", "masque-h2"}, {"aether", "unknown"}} {
		if _, err := AetherProfileCatalog(tc[0], tc[1]); err == nil {
			t.Fatalf("invalid mode/method accepted: %v", tc)
		}
	}
}

func TestAndroidAutomaticAetherMethodIsNotAdvertisedAsCrossMethodRace(t *testing.T) {
	raw, err := AetherProfileCatalog("aether", "auto")
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Methods []struct {
			ID    string `json:"id"`
			Title string `json:"title"`
		} `json:"methods"`
		Note string `json:"note"`
	}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, choice := range result.Methods {
		if choice.ID == "auto" {
			found = true
			if choice.Title != "Automatic (first compatible profile)" {
				t.Fatalf("Android claims to compare methods without implementing it: %q", choice.Title)
			}
		}
	}
	if !found || !strings.Contains(result.Note, "first compatible profile") {
		t.Fatalf("inaccurate automatic method description: %+v", result)
	}
}
