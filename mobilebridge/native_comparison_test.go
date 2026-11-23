package mobilebridge

import (
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
)

func TestNativeComparisonPrioritizesApplicationSuccess(t *testing.T) {
	stable := nativeComparisonSample{successes: 8, attempts: 8, latency: time.Second, bytesPerSecond: 1024}
	fast := nativeComparisonSample{successes: 7, attempts: 8, latency: time.Millisecond, bytesPerSecond: 1 << 20}
	if !betterNativeSample(stable, fast) || betterNativeSample(fast, stable) {
		t.Fatal("throughput overrides actual successful requests")
	}
	fast.successes = 8
	if !betterNativeSample(fast, stable) {
		t.Fatal("equal-success measured throughput not considered")
	}
}

func TestNativeComparisonCandidatesAreBoundedAndDiverse(t *testing.T) {
	profiles := []aether.Profile{
		{Label: "v4", Args: []string{"--masque", "--h2"}},
		{Label: "v4 duplicate", Args: []string{"--masque", "--h2"}},
		{Label: "v4 alt", Args: []string{"--masque", "--h2", "--fragment"}},
		{Label: "v6", Args: []string{"--masque", "--h2", "-6"}},
		{Label: "h3", Args: []string{"--masque", "--h3"}},
		{Label: "ech", Args: []string{"--masque", "--h2", "--ech", "auto"}},
	}
	got := nativeComparisonCandidates(profiles)
	if len(got) != 3 || got[0].Label != "v4" || got[1].Label != "v6" || got[2].Label != "v4 alt" {
		t.Fatalf("unexpected native comparison inventory: %v", got)
	}
}
