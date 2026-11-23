package revive

import (
	"encoding/json"
	"testing"
)

func TestPinnedServerlessVariants(t *testing.T) {
	for _, variant := range []string{"A", "B", "OOB"} {
		t.Run(variant, func(t *testing.T) {
			data, err := SelectPinnedProfileOnPort(variant, 11813)
			if err != nil {
				t.Fatal(err)
			}
			var value struct {
				Remarks string `json:"remarks"`
				Version struct {
					Min string `json:"min"`
				} `json:"version"`
				Inbounds []struct {
					Listen string `json:"listen"`
					Port   int    `json:"port"`
				} `json:"inbounds"`
			}
			if err := json.Unmarshal(data, &value); err != nil {
				t.Fatal(err)
			}
			if value.Version.Min != "26.11.23" || len(value.Inbounds) != 1 ||
				value.Inbounds[0].Listen != "127.0.0.1" || value.Inbounds[0].Port != 11813 {
				t.Fatalf("unsafe pinned profile: %+v", value)
			}
		})
	}
}
