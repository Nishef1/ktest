package revive

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestPinnedFamilyKeepsNumericDestination(t *testing.T) {
	for _, variant := range []string{"A", "B", "OOB"} {
		original, err := SelectPinnedProfileOnPort(variant, DefaultPort)
		if err != nil {
			t.Fatal(err)
		}
		both, err := SelectPinnedProfileForFamily(variant, DefaultPort, "both")
		if err != nil || !bytes.Equal(original, both) {
			t.Fatal("dual-stack must preserve the pinned profile")
		}
		for _, family := range []string{"ipv4", "ipv6"} {
			payload, err := SelectPinnedProfileForFamily(variant, DefaultPort, family)
			if err != nil {
				t.Fatal(err)
			}
			var config struct {
				Inbounds []struct {
					Sniffing map[string]any `json:"sniffing"`
				} `json:"inbounds"`
				Outbounds []struct {
					Settings map[string]any `json:"settings"`
				} `json:"outbounds"`
			}
			if err := json.Unmarshal(payload, &config); err != nil {
				t.Fatal(err)
			}
			if len(config.Inbounds) != 1 || config.Inbounds[0].Sniffing["routeOnly"] != true {
				t.Fatal("sniffing may overwrite the selected numeric address")
			}
			for _, out := range config.Outbounds {
				if _, ok := out.Settings["redirect"]; ok {
					t.Fatal("redirect can replace the selected address")
				}
			}
		}
	}
}
