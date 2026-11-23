package mobilebridge

import (
	"testing"

	"github.com/Nishef1/ktest/internal/aether"
)

func TestNativeTLSHistoryOnlyPromotesMatchingInventory(t *testing.T) {
	dir := t.TempDir()
	a := aether.Profile{Label: "a", Args: []string{"--masque", "--h2", "--masque-sni", "a.example.com"}}
	b := aether.Profile{Label: "b", Args: []string{"--masque", "--h2", "--masque-sni", "b.example.com"}}
	saveNativeTLSHistory(dir, "network-core-settings", b)
	profiles := []aether.Profile{a, b}
	if got := preferNativeTLSHistory(profiles, dir, "network-core-settings"); got[0].Label != "b" || got[1].Label != "a" {
		t.Fatalf("verified runtime winner not promoted: %v", got)
	}
	if got := preferNativeTLSHistory(profiles, dir, "different-network"); got[0].Label != "a" {
		t.Fatal("winner reused across networks")
	}
	if got := preferNativeTLSHistory([]aether.Profile{a}, dir, "network-core-settings"); got[0].Label != "a" {
		t.Fatal("cache introduced a profile outside the current inventory")
	}
	if err := saveNativeTLSHistory(dir, "second-network", a); err != nil {
		t.Fatal(err)
	}
	if got := preferNativeTLSHistory(profiles, dir, "network-core-settings"); got[0].Label != "b" {
		t.Fatal("switching networks erased verified history")
	}
}
