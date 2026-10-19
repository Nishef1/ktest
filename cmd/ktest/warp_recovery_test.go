package main

import (
	"context"
	"testing"
	"time"
)

func recoveryProfile(label string, args ...string) aetherProfile {
	return aetherProfile{Label: label, Args: args}
}

func TestBalancedDiscoveryAllowsIndependentBackendStartupBudget(t *testing.T) {
	m := &warpManager{o: connectOptions{mode: ModeBalanced}, profs: []aetherProfile{
		recoveryProfile("warp", "--masque", "--h2"),
		recoveryProfile("psiphon", "--psiphon-only"),
		recoveryProfile("tor", "--tor-only"),
	}}
	if got := m.searchBudget([]int{0, 1, 2}); got < profileAttemptBudget(m.profs[2]) {
		t.Fatalf("mixed discovery truncates Tor startup: %s", got)
	}
	if got := m.searchBudget([]int{0, 1, 0}); got < profileAttemptBudget(m.profs[1]) {
		t.Fatalf("mixed discovery truncates Psiphon startup: %s", got)
	}
}

func profileLabels(profiles []aetherProfile) []string {
	var labels []string
	for _, p := range profiles {
		labels = append(labels, p.Label)
	}
	return labels
}

func TestRecoveryTriesIndependentMethodsBeforeVariantsOfOneTransport(t *testing.T) {
	profiles := []aetherProfile{
		recoveryProfile("masque a"),
		recoveryProfile("masque b", "--endpoint", "b"),
		recoveryProfile("wireguard", "--wg"),
		recoveryProfile("cdn", "--psiphon-only", "--psiphon-mode", "cdn"),
	}
	got := profileLabels(recoveryProfilesFirst(profiles, networkProfile{}, ModeAether))
	want := []string{"masque a", "cdn", "wireguard", "masque b"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestRecoveryKeepsProvenFirstAndRecentFailuresLast(t *testing.T) {
	profiles := []aetherProfile{
		recoveryProfile("failed", "--wg"),
		recoveryProfile("untried"),
		recoveryProfile("proven", "--h2"),
	}
	history := networkProfile{Results: map[string]aetherMeasurement{
		profiles[0].ID(): {ID: profiles[0].ID(), State: "failed", Checked: time.Now().Add(-time.Minute)},
		profiles[2].ID(): {ID: profiles[2].ID(), State: "verified", Checked: time.Now().Add(-time.Minute), Attempts: 3, Successes: 3, LatencyMS: 80, ExitIP: "198.51.100.7", Country: "DE"},
	}}
	got := profileLabels(recoveryProfilesFirst(profiles, history, ModeAether))
	want := []string{"proven", "untried", "failed"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestRecoveryRetriesPromptlyUntilEveryProfileHadATurn(t *testing.T) {
	m := &warpManager{profs: []aetherProfile{recoveryProfile("a"), recoveryProfile("b", "--wg")}, attempted: map[string]bool{}}
	if len(m.remainingProfiles()) != 2 || m.recoveryDelay() != time.Second {
		t.Fatal("untried profiles must be retried after one second")
	}
	m.attempted[m.profs[0].ID()] = true
	if got := m.remainingProfiles(); len(got) != 1 || got[0] != 1 || m.recoveryDelay() != time.Second {
		t.Fatalf("remaining = %v", got)
	}
	var delays []time.Duration
	for range 4 {
		for _, p := range m.profs {
			m.attempted[p.ID()] = true
		}
		delays = append(delays, m.recoveryDelay())
		if m.attempted != nil {
			t.Fatal("a completed sweep must reset the ledger")
		}
		m.attempted = map[string]bool{}
	}
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 2 * time.Minute}
	for i := range want {
		if delays[i] != want[i] {
			t.Fatalf("backoff = %v, want %v", delays, want)
		}
	}
}

func TestVerifiedExitStartsAFreshOutage(t *testing.T) {
	m := &warpManager{profs: []aetherProfile{recoveryProfile("a"), recoveryProfile("b", "--wg")}, attempted: map[string]bool{}, failedSweeps: 2}
	m.attempted[m.profs[0].ID()] = true
	m.resetRecovery()
	if len(m.remainingProfiles()) != 2 || m.failedSweeps != 0 {
		t.Fatal("the profile that worked was excluded from the next recovery")
	}
}

// Recovery may reorder the *attempts*, but never the indexes of running cores.
func TestReplenishmentKeepsOriginalCorePortIndexes(t *testing.T) {
	profiles := []aetherProfile{
		recoveryProfile("h2", "--masque", "--h2"),
		recoveryProfile("wg", "--wg"),
		recoveryProfile("h3", "--masque", "--h3"),
	}
	m := &warpManager{profs: append([]aetherProfile(nil), profiles...)}
	history := networkProfile{Results: map[string]aetherMeasurement{
		profiles[2].ID(): {
			ID: profiles[2].ID(), State: "verified", Checked: time.Now(),
			Attempts: 3, Successes: 3, LatencyMS: 60, ExitIP: "198.51.100.9", Country: "DE",
		},
	}}
	indices := m.orderedCandidateIndices(nil, history)
	if len(indices) != 3 || indices[0] != 2 {
		t.Fatalf("measured profile did not lead recovery: %v", indices)
	}
	if m.profs[2].Label != "h3" {
		t.Fatal("recovery silently changed an existing core's port index")
	}
	active := map[string]*warpFound{profiles[2].ID(): {p: profiles[2]}}
	indices = m.orderedCandidateIndices(active, history)
	if len(indices) != 2 {
		t.Fatalf("expected only spare candidates, got %v", indices)
	}
	for _, i := range indices {
		if i == 2 {
			t.Fatalf("active core port was scheduled for reuse: %v", indices)
		}
	}
}

func TestReplenishmentWithEveryProfileActiveDoesNotRestartAnyCore(t *testing.T) {
	p := recoveryProfile("only", "--psiphon-only")
	m := &warpManager{profs: []aetherProfile{p}}
	if got := m.search(context.Background(), map[string]*warpFound{p.ID(): {p: p}}); len(got) != 0 {
		t.Fatal("restarted an active core")
	}
}
