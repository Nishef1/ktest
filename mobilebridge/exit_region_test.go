package mobilebridge

import "testing"

// An Iran-located WARP may carry ordinary sites in Aether but must never be
// marked eligible for AI destinations.
func TestForeignRegionGatesAIEligibility(t *testing.T) {
	if foreignRegion(observedExit{IP: "104.28.214.161", Region: "IR"}) {
		t.Fatal("an Iran-located exit was marked AI-eligible")
	}
	if !foreignRegion(observedExit{IP: "104.28.214.161", Region: "DE"}) {
		t.Fatal("a foreign exit was not AI-eligible")
	}
}
