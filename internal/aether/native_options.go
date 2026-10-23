package aether

import (
	"errors"
	"strings"
)

// NormalizeRegion validates a Psiphon exit country (two letters, e.g. DE) and
// returns it in upper case. Empty means Psiphon's own choice.
func NormalizeRegion(code string) (string, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return "", nil
	}
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return "", errors.New("Psiphon country must be a two-letter code such as DE")
	}
	return code, nil
}

// WithPsiphonRegion adds the exit country to a Psiphon profile; other profiles
// and profiles that already name a country are returned unchanged.
func WithPsiphonRegion(p Profile, region string) Profile {
	if region == "" || !p.Psiphon() || p.Has("--psiphon-region") {
		return p
	}
	return Profile{Label: p.Label, Args: append(append([]string(nil), p.Args...), "--psiphon-region", region)}
}

// StandaloneProfiles are the Psiphon or Tor profiles of a mode and method, in
// the order both the terminal and Android try them. In Psiphon mode Auto means
// the CDN-fronted variants only (plain Psiphon does not connect from Iran).
func StandaloneProfiles(mode, method string) ([]Profile, error) {
	if mode == "tor" {
		if method != "" && method != "auto" {
			return nil, errors.New("Tor uses its dedicated Aether backend")
		}
		return []Profile{{Label: "Tor-only", Args: []string{"--tor-only"}}}, nil
	}
	profiles, err := ParseProfiles(DefaultProfiles, "", "")
	if err != nil {
		return nil, err
	}
	profiles = FilterMethodForMode(ProfilesForMode(profiles, mode), method, mode)
	if len(profiles) == 0 {
		return nil, errors.New("selected method is incompatible with this mode")
	}
	return profiles, nil
}
