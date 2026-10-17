package aether

import (
	"path/filepath"
	"strings"
)

type IdentityRequirement struct {
	Protocol string `json:"protocol"`
	Name     string `json:"name"`
}

// IdentityRequirements is shared by readiness, enrollment and both clients.
// Standalone Tor/Psiphon have no WARP credentials. Nested identities are
// separate files, never aliases for the user's primary identity.
func IdentityRequirements(p Profile) []IdentityRequirement {
	if p.Psiphon() || p.Has("--tor-only") {
		return nil
	}
	method := p.Method()
	required := []IdentityRequirement{{Protocol: "masque", Name: "masque.toml"}}
	if method == "wireguard" || method == "wiw" {
		required[0] = IdentityRequirement{Protocol: "wg", Name: "wg.toml"}
	}
	switch method {
	case "wiw":
		required = append(required, IdentityRequirement{Protocol: "wg", Name: "wg-secondary.toml"})
	case "mim-h2", "mim-h3":
		required = append(required, IdentityRequirement{Protocol: "masque", Name: "masque-secondary.toml"})
	case "gool-h2", "gool-h3":
		required = append(required, IdentityRequirement{Protocol: "wg", Name: "masque-gool.toml"})
	}
	return required
}

func ReadyIdentity(p Profile, stateDir string) bool {
	for _, identity := range IdentityRequirements(p) {
		if CheckIdentity(filepath.Join(stateDir, identity.Name), identity.Protocol) != nil {
			return false
		}
	}
	return true
}

// GoolOuterProfile bootstraps the inner identity using only outer MASQUE.
// Both separated and equals-form flags are accepted by the profile parser.
func GoolOuterProfile(p Profile) Profile {
	var args []string
	for i := 0; i < len(p.Args); i++ {
		arg := p.Args[i]
		switch {
		case arg == "--protocol" && i+1 < len(p.Args):
			args = append(args, arg, "masque")
			i++
		case strings.HasPrefix(arg, "--protocol="):
			args = append(args, "--protocol=masque")
		case arg == "--gool" || arg == "--wiw":
			args = append(args, "--masque")
		case arg == "--gool-peer":
			i++
		case strings.HasPrefix(arg, "--gool-peer="):
		default:
			args = append(args, arg)
		}
	}
	return Profile{Label: "Gool registration carrier " + p.Method(), Args: args}
}
