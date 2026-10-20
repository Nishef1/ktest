package main

import (
	"time"

	"github.com/Nishef1/ktest/internal/aether"
)

func (m *warpManager) automaticWARPDiscovery() bool {
	return !m.diagnosis && (m.o.mode == ModeAether || m.o.mode == ModeWindscribeAether) &&
		(m.o.aetherMethod == "" || m.o.aetherMethod == "auto")
}

// Use the native fast scan for the first automatic sweep, then revisit every
// candidate with its full configured scan. This changes only launch arguments:
// stored measurements, profile IDs and assigned ports keep the original profile.
func (m *warpManager) discoveryProfile(p aetherProfile) aetherProfile {
	if !m.automaticWARPDiscovery() || m.failedSweeps > 0 {
		return p
	}
	switch p.Method() {
	case "masque-h2", "masque-h3", "wireguard":
	default:
		return p // nested identity bootstrap needs its original startup budget
	}
	for _, flag := range []string{"--scan", "--turbo", "--balanced", "--thorough", "--verified", "--ironclad", "--peer", "--wg-peer"} {
		if p.Has(flag) {
			return p
		}
	}
	p.Args = append(append([]string(nil), p.Args...), "--scan", "turbo")
	return p
}

// Preserve measured winners, but give independent unmeasured methods a turn
// before trying many variants of the same blocked transport. Psiphon CDN is
// independent of WARP enrollment/gateways; mode filtering happens beforehand.
func recoveryProfilesFirst(profiles []aetherProfile, history networkProfile, mode ConnectionMode) []aetherProfile {
	ranked := measuredProfilesFirst(profiles, history, mode)
	var proven, unknown, failed []aetherProfile
	for _, p := range ranked {
		r, ok := history.Results[p.ID()]
		switch {
		case ok && time.Since(r.Checked) <= networkCacheTTL && time.Until(r.Checked) <= time.Minute && measurementScore(r, mode) < 1e12:
			proven = append(proven, p)
		case ok && time.Since(r.Checked) < 10*time.Minute && time.Until(r.Checked) <= time.Minute:
			failed = append(failed, p)
		default:
			unknown = append(unknown, p)
		}
	}
	var diverse, variants []aetherProfile
	seen := map[string]bool{}
	for _, p := range unknown {
		method := p.Method()
		if p.LocalCarrier() {
			method += "/local"
		} else if p.ExitNode() != "" {
			method += "/exit-node"
		}
		if seen[method] {
			variants = append(variants, p)
			continue
		}
		seen[method] = true
		diverse = append(diverse, p)
	}
	diverse = aether.IndependentProfilesFirst(diverse)
	return append(append(append(proven, diverse...), variants...), failed...)
}

// The session ledger guarantees progress even when persistent cache writes
// fail. A cancelled attempt is not retried until every remaining profile has
// had a turn. Only the manager accesses the ledger outside compare's workers.
func (m *warpManager) remainingProfiles() []int {
	var indices []int
	for i, p := range m.profs {
		if !m.attempted[p.ID()] {
			indices = append(indices, i)
		}
	}
	return indices
}

func (m *warpManager) recoveryDelay() time.Duration {
	if len(m.remainingProfiles()) > 0 {
		return time.Second
	}
	m.attempted = nil
	m.failedSweeps++
	switch m.failedSweeps {
	case 1:
		return 30 * time.Second
	case 2:
		return time.Minute
	default:
		return 2 * time.Minute
	}
}

// A verified exit starts a fresh outage: the profile that just worked must be
// the first one retried when it dies, not excluded as already attempted.
func (m *warpManager) resetRecovery() {
	m.attempted = nil
	m.failedSweeps = 0
}
