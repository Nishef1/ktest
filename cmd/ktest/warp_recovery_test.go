package main

import (
	"testing"
	"time"
)

func recoveryProfile(label string, args ...string) aetherProfile {
	return aetherProfile{Label: label, Args: args}
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
		profiles[0].id(): {ID: profiles[0].id(), State: "failed", Checked: time.Now().Add(-time.Minute)},
		profiles[2].id(): {ID: profiles[2].id(), State: "verified", Checked: time.Now().Add(-time.Minute), Attempts: 3, Successes: 3, LatencyMS: 80, ExitIP: "198.51.100.7", Country: "DE"},
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
	m.attempted[m.profs[0].id()] = true
	if got := m.remainingProfiles(); len(got) != 1 || got[0] != 1 || m.recoveryDelay() != time.Second {
		t.Fatalf("remaining = %v", got)
	}
	var delays []time.Duration
	for range 4 {
		for _, p := range m.profs {
			m.attempted[p.id()] = true
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
	m.attempted[m.profs[0].id()] = true
	m.resetRecovery()
	if len(m.remainingProfiles()) != 2 || m.failedSweeps != 0 {
		t.Fatal("the profile that worked was excluded from the next recovery")
	}
}
