package aether

import (
	"errors"
	"fmt"
	"net"
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
	if region == "" || !(p.Psiphon() || p.ChainFlag() == "--psiphon") || p.Has("--psiphon-region") {
		return p
	}
	return Profile{Label: p.Label, Args: append(append([]string(nil), p.Args...), "--psiphon-region", region)}
}

// StandaloneProfiles are the Psiphon or Tor profiles of a mode and method, in
// the order both the terminal and Android try them: through WARP first (Aether
// first, as in Oblivion), then on their own. In Psiphon mode Auto leaves out
// plain Psiphon, which does not connect from Iran.
func StandaloneProfiles(mode, method string) ([]Profile, error) {
	profiles, err := ParseProfiles(DefaultProfiles, "", "")
	if err != nil {
		return nil, err
	}
	if mode == "tor" {
		profiles = append(profiles, Profile{Label: "Tor-only", Args: []string{"--tor-only"}})
	}
	profiles = FilterMethodForMode(ProfilesForMode(profiles, mode), method, mode)
	if len(profiles) == 0 {
		return nil, errors.New("selected method is incompatible with this mode")
	}
	return profiles, nil
}

// ExposeChain makes a Psiphon or Tor chain profile (see Profile.ChainFlag)
// answer on the given port. Aether serves the WARP exit on --bind and the chain
// on --psiphon-bind or --tor-bind; KTest verifies and routes through the chain,
// so the WARP proxy moves to a spare loopback port. Other profiles are returned
// unchanged.
func ExposeChain(p Profile, args []string, port int) ([]string, error) {
	flag := p.ChainFlag()
	if flag == "" {
		return args, nil
	}
	spare, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	inner := spare.Addr().String()
	_ = spare.Close() // Aether binds its own socket
	bind := "--psiphon-bind"
	if flag == "--tor" {
		bind = "--tor-bind"
	}
	out := append([]string(nil), args...)
	replaced := false
	for i := 0; i+1 < len(out); i++ {
		if out[i] == "--bind" {
			out[i+1], replaced = inner, true
		}
	}
	if !replaced {
		return nil, fmt.Errorf("%s profile has no --bind to move", strings.TrimPrefix(flag, "--"))
	}
	return append(out, bind, fmt.Sprintf("127.0.0.1:%d", port)), nil
}
