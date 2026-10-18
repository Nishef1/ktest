package mobilebridge

import (
	"encoding/json"
	"errors"
	"runtime"

	"github.com/Nishef1/ktest/internal/aether"
)

// AetherProfileCatalog exposes the exact CLI method/profile policy to Android.
// It never runs a core, registers an identity, or implies a working tunnel.
func AetherProfileCatalog(mode, method string) (string, error) {
	switch mode {
	case "balanced", "fast", "aether", "psiphon", "windscribe-aether", "tor":
	case "windscribe":
		return "", errors.New("local Windscribe mode prohibits managed Aether profiles")
	default:
		return "", errors.New("unknown connection mode")
	}
	if !aether.ValidMethod(method) {
		return "", errors.New("unknown Aether method")
	}
	profiles, err := aether.ParseProfiles(aether.DefaultProfiles, "", "")
	if err != nil {
		return "", err
	}
	var methods []aether.Method
	if mode == "tor" {
		if method != "" && method != "auto" {
			return "", errors.New("Tor uses its dedicated managed core path, not WARP method selection")
		}
		profiles = []aether.Profile{{Label: "Tor-only", Args: []string{"--tor-only"}}}
		methods = []aether.Method{{ID: "auto", Title: "Managed Tor-only"}}
	} else {
		profiles = aether.ProfilesForMode(profiles, mode)
		compatible := map[string]bool{"auto": true}
		for _, profile := range profiles {
			compatible[profile.Method()] = true
		}
		for _, choice := range aether.Methods() {
			if compatible[choice.ID] {
				if choice.ID == "auto" {
					// Android currently launches the first compatible
					// profile; Aether then measures gateways *within* it.
					// Do not imply ktest races different native methods.
					choice.Title = "Automatic (first compatible profile)"
				}
				methods = append(methods, choice)
			}
		}
		profiles = aether.FilterMethod(profiles, method)
		if len(profiles) == 0 {
			return "", errors.New("selected Aether method is incompatible with this connection mode")
		}
	}
	type entry struct {
		ID         string                       `json:"id"`
		Label      string                       `json:"label"`
		Method     string                       `json:"method"`
		Identities []aether.IdentityRequirement `json:"identities"`
	}
	var entries []entry
	for _, profile := range profiles {
		entries = append(entries, entry{ID: profile.ID(), Label: profile.Label, Method: profile.Method(), Identities: aether.IdentityRequirements(profile)})
	}
	raw, err := json.Marshal(struct {
		Methods  []aether.Method `json:"methods"`
		Profiles []entry         `json:"profiles"`
		Note     string          `json:"note"`
	}{methods, entries, "Shared CLI profiles without ECH-dependent variants. Android Auto starts the first compatible profile; Aether selects gateways within that method. Native availability and live egress require separate checks."})
	return string(raw), err
}

// InspectAndroidBundle verifies signed-package native files against the same
// pinned manifest used by packaging. This is disk I/O: call it from a worker.
func InspectAndroidBundle(nativeLibraryDir string) (string, error) {
	paths, err := aether.AndroidBundlePaths(nativeLibraryDir, runtime.GOARCH)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(paths)
	return string(raw), err
}
