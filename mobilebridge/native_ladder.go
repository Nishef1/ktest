package mobilebridge

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
)

// Settings the app applies before each connection, like SetAetherTLS.
var (
	nativeSettingsMu sync.Mutex
	psiphonRegion    string // upper-case ISO country code, "" = Psiphon's choice
	viaAetherFirst   = true
)

// SetPsiphonRegion asks Psiphon to leave from one country (for example DE).
// An empty value lets Psiphon choose.
func SetPsiphonRegion(code string) error {
	code, err := aether.NormalizeRegion(code)
	if err != nil {
		return err
	}
	nativeSettingsMu.Lock()
	psiphonRegion = code
	nativeSettingsMu.Unlock()
	return nil
}

// SetNativeViaAether chooses whether Psiphon and Tor first try to ride a
// verified Aether (WARP) tunnel before dialing out on their own.
func SetNativeViaAether(on bool) {
	nativeSettingsMu.Lock()
	viaAetherFirst = on
	nativeSettingsMu.Unlock()
}

func currentPsiphonRegion() string {
	nativeSettingsMu.Lock()
	defer nativeSettingsMu.Unlock()
	return psiphonRegion
}

func currentViaAetherFirst() bool {
	nativeSettingsMu.Lock()
	defer nativeSettingsMu.Unlock()
	return viaAetherFirst
}

// Bounds of the ladder. Through WARP a chain connects in seconds once WARP is
// up; standalone CDN variants scan fewer edges, so later ones get less time.
const (
	ladderChainBudget   = 150 * time.Second
	ladderVariantBudget = 70 * time.Second
)

// launchPsiphonTorLadder connects Psiphon or Tor, Aether first: the chain
// profiles run them inside a WARP tunnel (as Oblivion's Psiphon mode does),
// then the standalone profiles dial out on their own (through the local
// anti-DPI carrier if enabled). Every rung must pass the foreign-exit
// verification of the mode, and a failed rung is stopped before the next.
func launchPsiphonTorLadder(ctx context.Context, mode string, o nativeOptions) (*nativeCore, observedExit, error) {
	profiles, err := aether.StandaloneProfiles(mode, o.method)
	if err != nil {
		return nil, observedExit{}, err
	}
	if !currentViaAetherFirst() {
		var own []aether.Profile
		for _, p := range profiles {
			if p.ChainFlag() == "" {
				own = append(own, p)
			}
		}
		if len(own) > 0 {
			profiles = own
		}
	}
	var failures []string
	for i, p := range profiles {
		if err := ctx.Err(); err != nil {
			return nil, observedExit{}, fmt.Errorf("%w; %s", err, strings.Join(failures, "; "))
		}
		budget := ladderVariantBudget
		switch {
		case p.ChainFlag() != "":
			budget = min(aether.AttemptTimeout(p)+15*time.Second, ladderChainBudget+60*time.Second)
		case i == 0 || p.Has("--tor-only"):
			budget = aether.AttemptTimeout(p)
		}
		if i == len(profiles)-1 {
			budget = time.Hour // the start context bounds the final rung
		}
		candidate := o
		candidate.profile = &p
		attempt, cancel := context.WithTimeout(ctx, budget)
		core, err := launchNative(attempt, mode, candidate)
		if err == nil {
			var checked observedExit
			if checked, err = waitNative(attempt, mode, core); err == nil {
				cancel()
				return core, checked, nil
			}
			core.stop()
		}
		cancel()
		failures = append(failures, fmt.Sprintf("%s: %v", p.Label, err))
	}
	return nil, observedExit{}, fmt.Errorf("%s did not connect: %s", mode, strings.Join(failures, "; "))
}
