package mobilebridge

import (
	"context"
	"errors"
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
// An empty value lets Psiphon choose. Anything else than two letters is refused.
func SetPsiphonRegion(code string) error {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code != "" {
		if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
			return errors.New("Psiphon country must be a two-letter code such as DE")
		}
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

// Bounds of the Aether-first ladder. The bare-Psiphon rungs get what is left.
const (
	ladderWarpBudget    = 90 * time.Second
	ladderPsiphonBudget = 110 * time.Second
	ladderTorViaWarp    = 4 * time.Minute
	ladderVariantBudget = 70 * time.Second // narrower CDN sets scan fewer edges
	ladderWarpVariants  = 2
)

// ladderProfiles are the Psiphon or Tor profiles to try for a mode. Auto used to
// try only Psiphon's automatic shape, so a network that blocks everything but
// CDNs never reached the fronted path.
func ladderProfiles(mode, method string) ([]aether.Profile, error) {
	if mode == "tor" {
		if method != "" && method != "auto" {
			return nil, errors.New("Tor uses its dedicated Aether backend")
		}
		return []aether.Profile{{Label: "Tor-only", Args: []string{"--tor-only"}}}, nil
	}
	profiles, err := aether.ParseProfiles(aether.DefaultProfiles, "", "")
	if err != nil {
		return nil, err
	}
	profiles = aether.FilterMethodForMode(aether.ProfilesForMode(profiles, mode), method, mode)
	if len(profiles) == 0 {
		return nil, errors.New("selected method is incompatible with this mode")
	}
	return profiles, nil
}

// launchPsiphonTorLadder connects Psiphon or Tor in this order:
//  1. a verified Aether (WARP) tunnel, then Psiphon/Tor dialing through it;
//  2. Psiphon/Tor on their own (through the local anti-DPI carrier if enabled).
//
// Every rung must pass the foreign-exit verification of the mode. A rung that
// fails is stopped completely before the next one starts.
func launchPsiphonTorLadder(ctx context.Context, mode string, o nativeOptions) (*nativeCore, observedExit, error) {
	profiles, err := ladderProfiles(mode, o.method)
	if err != nil {
		return nil, observedExit{}, err
	}
	var failures []string
	try := func(p aether.Profile, carrier string, budget time.Duration) (*nativeCore, observedExit, error) {
		candidate := o
		candidate.profile = &p
		candidate.carrier = carrier
		attempt, cancel := context.WithTimeout(ctx, budget)
		defer cancel()
		core, err := launchNative(attempt, mode, candidate)
		if err != nil {
			return nil, observedExit{}, err
		}
		checked, err := waitNative(attempt, mode, core)
		if err != nil {
			core.stop()
			return nil, observedExit{}, err
		}
		return core, checked, nil
	}

	if currentViaAetherFirst() && mode != "aether" {
		warpOptions := o
		warpOptions.method, warpOptions.profile = "auto", nil
		warpCtx, stopWarp := context.WithTimeout(ctx, ladderWarpBudget)
		warp, _, warpErr := launchVerifiedNativeProfiles(warpCtx, warpOptions)
		stopWarp()
		if warpErr != nil {
			failures = append(failures, "Aether: "+warpErr.Error())
		} else {
			through := profiles
			if len(through) > ladderWarpVariants {
				through = through[:ladderWarpVariants]
			}
			for _, p := range through {
				budget := ladderPsiphonBudget
				if mode == "tor" {
					budget = ladderTorViaWarp
				}
				core, checked, err := try(p, warp.address, budget)
				if err == nil {
					core.parents = append(core.parents, warp)
					return core, checked, nil
				}
				failures = append(failures, fmt.Sprintf("%s through Aether: %v", p.Label, err))
				if ctx.Err() != nil {
					break
				}
			}
			warp.stop()
		}
	}

	for i, p := range profiles {
		if err := ctx.Err(); err != nil {
			return nil, observedExit{}, fmt.Errorf("%w; %s", err, strings.Join(failures, "; "))
		}
		budget := ladderVariantBudget
		if i == 0 {
			budget = aether.AttemptTimeout(p)
		}
		if i == len(profiles)-1 {
			budget = time.Hour // the start context bounds the final rung
		}
		core, checked, err := try(p, o.carrier, budget)
		if err == nil {
			return core, checked, nil
		}
		failures = append(failures, fmt.Sprintf("%s: %v", p.Label, err))
	}
	return nil, observedExit{}, fmt.Errorf("%s did not connect: %s", mode, strings.Join(failures, "; "))
}

// withPsiphonRegion adds the selected exit country to a Psiphon profile.
func withPsiphonRegion(p aether.Profile) aether.Profile {
	region := currentPsiphonRegion()
	if region == "" || !p.Psiphon() || p.Has("--psiphon-region") {
		return p
	}
	return aether.Profile{Label: p.Label, Args: append(append([]string(nil), p.Args...), "--psiphon-region", region)}
}
