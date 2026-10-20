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

func TestAutomaticDiscoveryLetsFirstWorkersFinishNativeScans(t *testing.T) {
	m := &warpManager{o: connectOptions{mode: ModeAether}, profs: []aetherProfile{
		recoveryProfile("h2", "--masque", "--h2"),
		recoveryProfile("wg", "--wg"),
		recoveryProfile("h3", "--masque", "--h3"),
	}}
	if got := m.searchBudget([]int{0, 1, 2}); got < 200*time.Second {
		t.Fatalf("automatic wave cancels initial native scans: %s", got)
	}
	// A later deep-scan variant must not inflate the current worker wave.
	m.profs = append(m.profs, recoveryProfile("deep", "--masque", "--thorough"))
	if got := m.searchBudget([]int{0, 1, 2, 3}); got > 4*time.Minute {
		t.Fatalf("unscheduled deep scan inflated first wave: %s", got)
	}
}

func TestQuickDiscoveryEscalatesAfterCompletedSweep(t *testing.T) {
	m := &warpManager{o: connectOptions{mode: ModeAether}, profs: []aetherProfile{
		recoveryProfile("h2", "--masque", "--h2"),
		recoveryProfile("wg", "--wg"),
		recoveryProfile("h3", "--masque", "--h3"),
	}}
	m.attempted = map[string]bool{}
	for _, p := range m.profs {
		if got := m.discoveryProfile(p); got.Value("--scan") != "turbo" {
			t.Fatalf("first sweep did not use native quick discovery: %v", got.Args)
		}
		m.attempted[p.ID()] = true
	}
	if m.recoveryDelay() != 30*time.Second {
		t.Fatal("quick sweep did not finish")
	}
	for _, p := range m.profs {
		if got := m.discoveryProfile(p); got.Has("--scan") {
			t.Fatalf("full recovery remained on a shortened scan: %v", got.Args)
		}
	}
}

func TestQuickDiscoveryPreservesExplicitPoliciesAndProfileIdentity(t *testing.T) {
	p := recoveryProfile("h2", "--masque", "--h2")
	for _, mode := range []ConnectionMode{ModeAether, ModeWindscribeAether} {
		m := &warpManager{o: connectOptions{mode: mode}}
		got := m.discoveryProfile(p)
		if got.Value("--scan") != "turbo" || attemptTimeout(got) >= attemptTimeout(p) {
			t.Fatalf("%s did not use native quick discovery: %v", mode, got.Args)
		}
		if p.Has("--scan") || p.ID() != recoveryProfile("h2", "--masque", "--h2").ID() {
			t.Fatal("runtime scan policy changed the saved profile")
		}
	}
	for _, tc := range []struct {
		name string
		m    *warpManager
		p    aetherProfile
	}{
		{"forced method", &warpManager{o: connectOptions{mode: ModeAether, aetherMethod: "masque-h2"}}, p},
		{"diagnosis", &warpManager{o: connectOptions{mode: ModeAether}, diagnosis: true}, p},
		{"mixed policy", &warpManager{o: connectOptions{mode: ModeBalanced}}, p},
		{"explicit scan", &warpManager{o: connectOptions{mode: ModeAether}}, recoveryProfile("deep", "--masque", "--scan=thorough")},
		{"scan alias", &warpManager{o: connectOptions{mode: ModeAether}}, recoveryProfile("deep", "--masque", "--balanced")},
		{"forced peer", &warpManager{o: connectOptions{mode: ModeAether}}, recoveryProfile("peer", "--masque", "--peer", "162.159.198.8:443")},
		{"nested identity", &warpManager{o: connectOptions{mode: ModeAether}}, recoveryProfile("nested", "--gool", "--h2")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.m.discoveryProfile(tc.p); got.ID() != tc.p.ID() {
				t.Fatalf("explicit or independent policy changed: %v -> %v", tc.p.Args, got.Args)
			}
		})
	}
}

func TestAetherWinnerIsReusedForWindscribeThroughAether(t *testing.T) {
	base := t.TempDir()
	profiles, err := loadAetherProfiles(base, "ECH", "1.1.1.1", ModeAether)
	if err != nil {
		t.Fatal(err)
	}
	var winner aetherProfile
	for _, p := range profiles {
		if p.Method() == "masque-h2" && !p.Has("--ech") && !p.Has("--fragment") && !p.Has("--upstream") {
			winner = p
			break
		}
	}
	if winner.Label == "" {
		t.Fatal("plain H2 carrier is unavailable")
	}
	history := networkProfile{Results: map[string]aetherMeasurement{
		winner.ID(): {State: "carrier", Checked: time.Now(), Attempts: 9, Successes: 8, LatencyMS: 531, ExitIP: "104.28.246.163", Country: "IR"},
	}}
	for _, mode := range []ConnectionMode{ModeAether, ModeWindscribeAether} {
		candidates, err := loadAetherProfiles(base, "fresh ECH", "1.0.0.1", mode)
		if err != nil {
			t.Fatal(err)
		}
		ordered := recoveryProfilesFirst(candidates, history, mode)
		if len(ordered) == 0 || ordered[0].ID() != winner.ID() {
			t.Fatalf("%s did not reuse the working Aether carrier first: %v", mode, profileLabels(ordered))
		}
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
