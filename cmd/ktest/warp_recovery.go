package main

import "time"

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
		}
		if seen[method] {
			variants = append(variants, p)
			continue
		}
		seen[method] = true
		diverse = append(diverse, p)
	}
	if len(diverse) > 1 {
		for i := 1; i < len(diverse); i++ {
			if diverse[i].Method() == "psiphon-cdn" {
				p := diverse[i]
				copy(diverse[2:i+1], diverse[1:i])
				diverse[1] = p
				break
			}
		}
	}
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
