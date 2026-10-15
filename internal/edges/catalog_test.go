package edges

import (
	"context"
	"testing"
)

func TestAkamaiPresetIsSmallAndSourceAttributed(t *testing.T) {
	p, err := PresetCandidates(context.Background(), "akamai")
	if err != nil {
		t.Fatal(err)
	}
	if p.Provider != "akamai" || len(p.IPs) == 0 || len(p.IPs) > 12 || p.Source == "" || p.URL == "" {
		t.Fatalf("invalid source-backed preset: %+v", p)
	}
	for _, ip := range p.IPs {
		if ip == "127.0.0.1" {
			t.Fatal("local addresses must not be seeds")
		}
	}
}

func TestUnknownPresetRejectedWithoutNetwork(t *testing.T) {
	if _, err := PresetCandidates(context.Background(), "unknown"); err == nil {
		t.Fatal("unknown provider accepted")
	}
}
