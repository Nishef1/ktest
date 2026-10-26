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
	viaAetherFirst   = false // Psiphon Auto is independent by default; WARP-first is explicit
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

// SetNativeViaAether chooses whether Psiphon Auto tries WARP first.
// Tor is standalone in KTest and never consults this setting.
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

// launchPsiphonTorLadder tries independent Psiphon CDN profiles, or
// Psiphon-through-WARP first when explicitly requested and keys already
// exist. Each rung must prove a foreign exit before it is promoted. A
// failed Fast carrier is retried directly, not treated as an ISP failure.
func launchPsiphonTorLadder(ctx context.Context, mode string, o nativeOptions) (*nativeCore, observedExit, error) {
	profiles, err := aether.StandaloneProfiles(mode, o.method)
	if err != nil {
		return nil, observedExit{}, err
	}
	if mode == "psiphon" && (o.method == "" || o.method == "auto") {
		var direct, chain []aether.Profile
		for _, p := range profiles {
			if p.ChainFlag() == "" {
				direct = append(direct, p)
			} else if aether.ReadyIdentity(p, o.stateDir) {
				// Do not spend the first attempt registering WARP keys
				// when the user only needs a standalone Psiphon exit.
				chain = append(chain, p)
			}
		}
		if currentViaAetherFirst() && len(chain) > 0 {
			profiles = append(chain, direct...)
		} else {
			profiles = direct
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
		// A local Fast helper must never replace independent Psiphon
		// dialing. A successful Fast listener is not evidence that it can
		// reach the CDN, so retry standalone Psiphon directly as well.
		carriers := []string{o.carrier}
		if o.carrier != "" && p.ChainFlag() == "" {
			carriers = append(carriers, "")
		}
		for _, carrier := range carriers {
			candidate := o
			candidate.carrier = carrier
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
			route := "direct"
			if carrier != "" {
				route = "Fast carrier"
			}
			failures = append(failures, fmt.Sprintf("%s (%s): %v", p.Label, route, err))
		}
	}
	return nil, observedExit{}, fmt.Errorf("%s did not connect: %s", mode, strings.Join(failures, "; "))
}
