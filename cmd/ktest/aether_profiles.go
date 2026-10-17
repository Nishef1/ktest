package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func validAetherMethod(method string) bool {
	switch method {
	case "", "auto", "masque-h2", "masque-h3", "wireguard", "gool-h2", "gool-h3", "wiw", "mim-h2", "mim-h3", "psiphon", "psiphon-cdn":
		return true
	}
	return false
}

func (p aetherProfile) method() string {
	suffix := "-h3"
	if p.has("--h2") || p.has("--http2") {
		suffix = "-h2"
	}
	switch {
	case p.psiphon():
		if p.value("--psiphon-mode") == "cdn" {
			return "psiphon-cdn"
		}
		return "psiphon"
	case p.has("--tor-only"):
		return "tor"
	case p.has("--gool-classic") || p.has("--wiw-outer") || p.has("--wiw-inner") || p.has("--wiw-peers"):
		return "wiw"
	case p.has("--gool") || p.has("--wiw") || p.value("--protocol") == "gool":
		return "gool" + suffix
	case p.has("--mim") || p.has("--masque-in-masque") || p.value("--protocol") == "mim":
		return "mim" + suffix
	case p.has("--wg") || p.has("--wireguard") || p.has("--warp") || p.value("--protocol") == "wg":
		return "wireguard"
	default:
		return "masque" + suffix
	}
}

func (p aetherProfile) value(flag string) string {
	for i, v := range p.Args {
		if v == flag && i+1 < len(p.Args) {
			return p.Args[i+1]
		}
	}
	return ""
}

// ECH retry configurations are short-lived discovery data, not profile identity.
// Stable IDs keep endpoint files associated with the same transport after sorting.
func (p aetherProfile) id() string {
	args := append([]string(nil), p.Args...)
	for i, flag := range args {
		if (flag == "--ech" || flag == "--enroll-address") && i+1 < len(args) {
			args[i+1] = "<discovered>"
		}
	}
	sum := sha256.Sum256([]byte(p.Label + "\n" + strings.Join(args, "\x00")))
	return hex.EncodeToString(sum[:8])
}

func filterAetherMethod(profiles []aetherProfile, method string) []aetherProfile {
	if method == "" || method == "auto" {
		return profiles
	}
	var selected []aetherProfile
	for _, p := range profiles {
		if p.method() == method {
			selected = append(selected, p)
		}
	}
	return selected
}

// Saved recommendations and live launches use the same transport boundary.
func profilesForMode(profiles []aetherProfile, mode ConnectionMode) []aetherProfile {
	var selected []aetherProfile
	for _, p := range profiles {
		if mode == ModeWindscribe {
			continue
		}
		if mode == ModePsiphon && (!p.psiphon() || p.has("--tor-only") || p.has("--masque") || p.has("--wg") || p.has("--gool") || p.has("--mim") || p.has("--gool-classic")) {
			continue
		}
		if mode == ModeWindscribeAether && (p.psiphon() || p.has("--tor-only") || p.has("--tor") || p.has("--psiphon") || p.has("--tor-reverse") || p.has("--psiphon-reverse") || p.has("--upstream")) {
			continue
		}
		selected = append(selected, p)
	}
	return selected
}

func supportedAetherProfiles(ctx context.Context, bin string, profiles []aetherProfile) ([]aetherProfile, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--help")
	hideConsole(cmd)
	help, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("cannot inspect Aether capabilities: %w", err)
	}
	var supported []aetherProfile
	for _, p := range profiles {
		ok := true
		for _, arg := range p.Args {
			if strings.HasPrefix(arg, "--") && !strings.Contains(string(help), arg) {
				ok = false
				break
			}
		}
		if ok {
			supported = append(supported, p)
		}
	}
	return supported, nil
}
