// Package aether owns the existing KTest Aether profile and identity contracts.
// It is shared by CLI and Android; it does not implement a second tunnel core.
package aether

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// DefaultProfiles is the shipped list; profiles/aether-profiles.txt
// replaces it. {ECH} and {ECHIP} are an ECH configuration and a Cloudflare edge
// address that ktest fetched itself, with no DNS: they make the calls to the
// WARP API (the key) possible where the API's name is filtered. A line that uses
// them is skipped when they could not be fetched.
const DefaultProfiles = `# Aether profiles, one per line:  label | flags
# ktest adds the loopback bind address, identity files and registration answers.
# Community reports on 2026-10-21 say cloudflare-ech.com SNI is filtered on some
# Iranian networks. Keep non-ECH paths first; this is a fallback inventory, not
# a claim that the same firewall applies to every SIM or region.
WARP, MASQUE over HTTP/2 | --masque --h2
WARP, MASQUE over HTTP/2, IPv6 | --masque --h2 -6
WARP, MASQUE over HTTP/2, fragmented | --masque --h2 --fragment
WARP, MASQUE over HTTP/3 | --masque --h3
WARP, WireGuard without ECH enrollment | --wg --noize balanced
WARP, WireGuard IPv6 | --wg --noize balanced -6
# ECH-dependent variants remain as later fallbacks when the visible public name works.
WARP, MASQUE over HTTP/2 with ECH | --masque --h2 --fragment --ech {ECH} --api-address {ECHIP}
WARP, MASQUE over HTTP/2 with ECH, IPv6 | --masque --h2 -6 --ech {ECH} --api-address {ECHIP}
WARP, MASQUE over HTTP/3 with ECH | --masque --h3 --ech {ECH} --api-address {ECHIP}
WARP, WireGuard with ECH enrollment | --wg --noize balanced --ech {ECH} --api-address {ECHIP}
WARP, WireGuard IPv6 with ECH enrollment | --wg --noize balanced -6 --ech {ECH} --api-address {ECHIP}
# Runtime ECH fallback: Aether can fetch its own key when the independent
# bootstrap is filtered. It is attempted only after ordinary profiles.
WARP, MASQUE HTTP/2 with core-managed ECH | --masque --h2 --fragment --ech auto
WARP, MASQUE HTTP/3 with core-managed ECH | --masque --h3 --ech auto
WARP, Gool WireGuard over MASQUE H2 | --gool --h2
WARP, Gool WireGuard over MASQUE H3 | --gool --h3
WARP, MASQUE-in-MASQUE H2 | --mim --h2
WARP, MASQUE-in-MASQUE H3 | --mim --h3
WARP, classic WireGuard-in-WireGuard | --gool-classic
WARP, WireGuard, aggressive obfuscation | --wg --noize aggressive --ech {ECH} --api-address {ECHIP}
Psiphon through CDN fronting | --psiphon-only --psiphon-mode cdn
Psiphon | --psiphon-only
WARP, MASQUE over HTTP/2 with ECH, thorough scan | --masque --h2 --fragment --scan thorough --startup-secs 100 --ech {ECH} --api-address {ECHIP}
`

// Profile is one way of running Aether.
type Profile struct {
	Label string
	Args  []string
}

func (p Profile) Has(flag string) bool {
	for _, a := range p.Args {
		if a == flag || strings.HasPrefix(a, flag+"=") {
			return true
		}
	}
	return false
}

func (p Profile) Psiphon() bool { return p.Has("--psiphon-only") }

// ParseProfiles reads "label | flags" lines, substituting the ECH
// placeholders and dropping lines that need what is not available.
func ParseProfiles(text, ech, ip string) ([]Profile, error) {
	var out []Profile
	seen := map[string]bool{}
	for n, line := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		label, flags, ok := strings.Cut(line, "|")
		label, flags = strings.TrimSpace(label), strings.TrimSpace(flags)
		if !ok || label == "" || flags == "" {
			return nil, fmt.Errorf("line %d: want \"label | flags\"", n+1)
		}
		args := strings.Fields(flags)
		for _, arg := range args {
			name, _, _ := strings.Cut(arg, "=")
			switch name {
			case "--bind", "--config", "--masque-config", "--wg-config", "--http-proxy", "--tor-bind", "--psiphon-bind", "--register":
				return nil, fmt.Errorf("line %d: %s is managed by ktest", n+1, name)
			}
		}
		if strings.Contains(flags, "{ECH") && (ech == "" || ip == "") {
			continue
		}
		flags = strings.NewReplacer("{ECHIP}", ip, "{ECH}", ech).Replace(flags)
		if seen[label] {
			return nil, fmt.Errorf("line %d: duplicate label %q", n+1, label)
		}
		seen[label] = true
		out = append(out, Profile{Label: label, Args: strings.Fields(flags)})
		if len(out) > 64 {
			return nil, fmt.Errorf("at most 64 Aether profiles are supported")
		}
	}
	return out, nil
}

func ValidMethod(method string) bool {
	if method == "" {
		return true
	}
	for _, choice := range Methods() {
		if choice.ID == method {
			return true
		}
	}
	return false
}

// UsesMASQUE reports whether a method negotiates its transport through MASQUE.
// Keep this shared so the CLI and Android avoid measuring or applying MASQUE
// TLS-shape options to WireGuard, Psiphon, or Tor selections.
func UsesMASQUE(method string) bool {
	switch method {
	case "masque-h2", "masque-h3", "gool-h2", "gool-h3", "mim-h2", "mim-h3":
		return true
	default:
		return false
	}
}

func (p Profile) Method() string {
	suffix := "-h3"
	if p.Has("--h2") || p.Has("--http2") {
		suffix = "-h2"
	}
	switch {
	case p.Psiphon():
		if p.Value("--psiphon-mode") == "cdn" {
			return "psiphon-cdn"
		}
		return "psiphon"
	case p.Has("--tor-only"):
		return "tor"
	case p.Has("--gool-classic") || p.Has("--wiw-outer") || p.Has("--wiw-inner") || p.Has("--wiw-peers"):
		return "wiw"
	case p.Has("--gool") || p.Has("--wiw") || p.Value("--protocol") == "gool":
		return "gool" + suffix
	case p.Has("--mim") || p.Has("--masque-in-masque") || p.Value("--protocol") == "mim":
		return "mim" + suffix
	case p.Has("--wg") || p.Has("--wireguard") || p.Has("--warp") || p.Value("--protocol") == "wg":
		return "wireguard"
	default:
		return "masque" + suffix
	}
}

func (p Profile) Value(flag string) string {
	for i, v := range p.Args {
		if v == flag && i+1 < len(p.Args) {
			return p.Args[i+1]
		}
		if value, ok := strings.CutPrefix(v, flag+"="); ok {
			return value
		}
	}
	return ""
}

// QuickScanProfile is a first-pass launch policy. Callers retain the original
// profile for measurements and revisit its full scan after the quick pass.
// Explicit scan/peer choices and nested bootstrap keep their configured policy.
func QuickScanProfile(p Profile) Profile {
	switch p.Method() {
	case "masque-h2", "masque-h3", "wireguard":
	default:
		return p
	}
	for _, flag := range []string{"--scan", "--turbo", "--balanced", "--thorough", "--verified", "--ironclad", "--peer", "--wg-peer"} {
		if p.Has(flag) {
			return p
		}
	}
	p.Args = append(append([]string(nil), p.Args...), "--scan", "turbo")
	return p
}

// MASQUEScanFailed recognizes the native final result, rather than a low-level
// probe timeout that might still be followed by an internal fallback.
func MASQUEScanFailed(line string) bool {
	return strings.Contains(line, " aether]") && strings.Contains(line, "no usable MASQUE gateway found:")
}

// ECH retry configurations are short-lived discovery data, not profile identity.
// Stable IDs keep endpoint files associated with the same transport after sorting.
func (p Profile) ID() string {
	args := append([]string(nil), p.Args...)
	for i, flag := range args {
		if flag == "--enroll-address" {
			// The old and new API-address spellings describe the same route.
			flag, args[i] = "--api-address", "--api-address"
		}
		if flag == "--api-fragment" {
			flag, args[i] = "--fragment", "--fragment"
		}
		if (flag == "--ech" || flag == "--api-address") && i+1 < len(args) {
			args[i+1] = "<discovered>"
		}
		// The MASQUE name and fragment ranges are measured per network
		// (tlsshape); a new measurement keeps the profile's history.
		if (flag == "--masque-sni" || flag == "--fragment-size" || flag == "--fragment-delay") && i+1 < len(args) {
			args[i+1] = "<tuned>"
		}
		for _, key := range []string{"--masque-sni=", "--fragment-size=", "--fragment-delay="} {
			if strings.HasPrefix(flag, key) {
				args[i] = key + "<tuned>"
			}
		}
		for _, key := range []string{"--ech=", "--enroll-address=", "--api-address="} {
			if strings.HasPrefix(flag, key) {
				name := key
				if key == "--enroll-address=" {
					name = "--api-address="
				}
				args[i] = name + "<discovered>"
			}
		}
	}
	sum := sha256.Sum256([]byte(p.Label + "\n" + strings.Join(args, "\x00")))
	return hex.EncodeToString(sum[:8])
}

func FilterMethod(profiles []Profile, method string) []Profile {
	if method == "" || method == "auto" {
		return profiles
	}
	var selected []Profile
	for _, p := range profiles {
		if p.Method() == method {
			selected = append(selected, p)
		}
	}
	return selected
}

// Saved recommendations and live launches use the same transport boundary.
// ProfilesForMode enforces the advertised exit protocol, not merely whether
// a profile can produce a foreign IP. In particular, an Aether session must
// never silently become Psiphon/Tor, and a Tor session must never become WARP.
// Balanced is the explicit multi-backend policy; Fast permits only WARP.
func ProfilesForMode(profiles []Profile, mode string) []Profile {
	var selected []Profile
	for _, p := range profiles {
		psiphon := p.Psiphon()
		tor := p.Has("--tor-only")
		otherHelpers := p.Has("--tor") || p.Has("--psiphon") ||
			p.Has("--tor-reverse") || p.Has("--psiphon-reverse")
		hasWarp := p.Has("--masque") || p.Has("--wg") || p.Has("--wireguard") || p.Has("--warp") ||
			p.Has("--gool") || p.Has("--mim") ||
			p.Has("--gool-classic") || p.Value("--protocol") != ""
		switch mode {
		case "windscribe":
			continue
		case "aether", "windscribe-aether", "fast":
			if psiphon || tor || otherHelpers || (p.Has("--upstream") && !p.OwnedUpstream()) {
				continue
			}
			// Raw WARP carrier profiles are valid only when KTest owns their
			// loopback path; Windscribe-Aether must remain directly carried.
			if mode == "windscribe-aether" && p.Has("--upstream") {
				continue
			}
			// An empty/--h2-only Aether profile is valid: MASQUE is
			// the core's documented default. Reject helper backends above,
			// but do not reject a deliberate implicit MASQUE configuration.
		case "psiphon":
			if !psiphon || tor || otherHelpers || hasWarp || p.Has("--upstream") {
				continue
			}
		case "tor":
			if !tor || psiphon || otherHelpers || hasWarp || p.Has("--upstream") {
				continue
			}
		case "balanced":
			// Balanced is the only policy that intentionally mixes native
			// exit backends. Do not impose a transport preference here.
		default:
			continue
		}
		selected = append(selected, p)
	}
	return selected
}

// IndependentProfilesFirst preserves the leading recommendation, then gives
// WARP, Psiphon/CDN and Tor each a slot before further variants of a backend.
// Later rounds remain interleaved so a failed cached Psiphon profile cannot
// bury its CDN alternative behind every WARP variant. The inventory is unchanged.
func IndependentProfilesFirst(profiles []Profile) []Profile {
	if len(profiles) == 0 {
		return nil
	}
	family := func(p Profile) string {
		if p.Psiphon() {
			return "psiphon"
		}
		if p.Has("--tor-only") {
			return "tor"
		}
		return "warp"
	}
	selected := make(map[int]bool)
	selected[0] = true
	out := []Profile{profiles[0]}
	appendNext := func(kind string) bool {
		candidate := -1
		for i, p := range profiles {
			if selected[i] || family(p) != kind {
				continue
			}
			if candidate == -1 {
				candidate = i
			}
			if kind == "psiphon" && p.Method() == "psiphon-cdn" {
				candidate = i
				break
			}
		}
		if candidate >= 0 {
			selected[candidate] = true
			out = append(out, profiles[candidate])
			return true
		}
		return false
	}
	kinds := []string{"psiphon", "tor", "warp"}
	for _, kind := range kinds {
		if family(profiles[0]) != kind {
			appendNext(kind)
		}
	}
	for len(out) < len(profiles) {
		for _, kind := range kinds {
			appendNext(kind)
		}
	}
	return out
}

// The help output is not a bag of substrings. Read option declarations from
// their own lines so --h is not falsely accepted because --help exists.
func DocumentedOptions(help string) map[string]bool {
	known := make(map[string]bool)
	for _, line := range strings.Split(help, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-") {
			continue
		}
		for _, field := range strings.Fields(line) {
			for _, alias := range strings.Split(field, ",") {
				alias = strings.TrimSpace(alias)
				name, _, _ := strings.Cut(alias, "=")
				name = strings.TrimRight(name, ",|")
				if !strings.HasPrefix(name, "--") {
					continue
				}
				ok := len(name) > 2
				for _, c := range name[2:] {
					if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
						ok = false
						break
					}
				}
				if ok {
					known[name] = true
				}
			}
		}
	}
	return known
}

// RunArgs is the full command line of a profile on a local port. Every
// prompt Aether would ask has a flag here, so it never waits for input; flags
// the profile sets itself are not repeated.
func RunArgs(p Profile, port int, stateDir string) []string {
	args := append([]string(nil), p.Args...)
	has := func(flags ...string) bool {
		for _, f := range flags {
			if p.Has(f) {
				return true
			}
		}
		return false
	}
	if !p.Psiphon() && !p.Has("--tor-only") {
		if !has("-4", "-6", "--dual", "--ip") {
			args = append(args, "-4")
		}
		if !has("--scan", "--turbo", "--balanced", "--thorough", "--verified", "--ironclad") {
			args = append(args, "--balanced")
		}
		if !has("--startup-secs") {
			args = append(args, "--startup-secs", "45")
		}
		if !has("--quick-reconnect", "--no-quick-reconnect") {
			// As in PattNG, revalidate the core's remembered endpoints first.
			// Failed cached peers fall back to scanning; they never prove an exit.
			args = append(args, "--quick-reconnect")
		}
	}
	if !has("--log-level", "--verbose") {
		// Scan/selection milestones are INFO in the pinned core. WARN alone
		// leaves a healthy but unfinished scan with an empty diagnostic log.
		args = append(args, "--log-level", "info")
	}
	return append(args,
		"--bind", fmt.Sprintf("127.0.0.1:%d", port),
		"--config", filepath.Join(stateDir, "run-"+p.ID()+".toml"),
		"--masque-config", filepath.Join(stateDir, "masque.toml"),
		"--wg-config", filepath.Join(stateDir, "wg.toml"),
	)
}

// AttemptTimeout includes one complete native gateway scan, subsequent tunnel
// startup and a readiness margin. --startup-secs only starts AFTER selection.
// Native retries may continue beyond this bound; timeout is not proof of blocking.
func AttemptTimeout(p Profile) time.Duration {
	if p.Has("--tor-only") {
		return 7 * time.Minute
	}
	if p.Psiphon() {
		// Aether 2.3.0 gives its independent Psiphon helper 180 seconds to
		// establish a tunnel. WARP's 45-second startup budget cuts that short.
		return 200 * time.Second
	}
	startup := 45 * time.Second
	if duration, err := time.ParseDuration(p.Value("--startup-secs") + "s"); err == nil && duration >= 0 && duration <= time.Duration(1<<63-1)-10*time.Minute {
		startup = duration
	}
	return scanTimeout(p) + startup + 20*time.Second
}

// These scan deadlines come from v2.3.1 prober.rs / wg_prober.rs, the core
// pinned by PattNG and KTest. Forced peers skip discovery in that core.
func scanTimeout(p Profile) time.Duration {
	wg := p.Method() == "wireguard" || p.Method() == "wiw"
	if p.Has("--peer") || (wg && p.Has("--wg-peer")) {
		return 0
	}
	mode := p.Value("--scan")
	if mode == "" {
		for _, flag := range []string{"turbo", "balanced", "thorough", "verified", "ironclad"} {
			if p.Has("--" + flag) {
				mode = flag
				break
			}
		}
	}
	switch mode {
	case "turbo", "fast":
		if wg {
			return 30 * time.Second
		}
		return 45 * time.Second
	case "thorough", "deep", "pro":
		if wg {
			return 250 * time.Second
		}
		return 300 * time.Second
	case "verified", "proven", "stealth", "quiet":
		return 60 * time.Second
	case "ironclad", "real", "verify", "guaranteed":
		return 180 * time.Second
	default:
		if wg {
			return 80 * time.Second
		}
		return 120 * time.Second
	}
}

// adaptProfileFlags keeps the shipped and user-defined profile catalog usable
// with both the older 2.3.0 binary and the newer source used by PattNG.
// It changes only renamed/removed CLI flags and never silently drops an
// unknown transport option.
func adaptProfileFlags(p Profile, known map[string]bool) Profile {
	args := make([]string, 0, len(p.Args))
	for _, arg := range p.Args {
		name, value, inline := strings.Cut(arg, "=")
		replacement := name
		switch name {
		case "--enroll-address":
			if !known[name] && known["--api-address"] {
				replacement = "--api-address"
			}
		case "--api-address":
			if !known[name] && known["--enroll-address"] {
				replacement = "--enroll-address"
			}
		case "--api-fragment":
			if !known[name] && known["--fragment"] {
				replacement = "--fragment"
			}
		case "--no-fragment":
			// The new core defaults to no fragmentation; the old core
			// supported an explicit --no-fragment with the opposite default.
			if !known[name] && known["--fragment"] {
				continue
			}
		}
		if inline {
			args = append(args, replacement+"="+value)
		} else {
			args = append(args, replacement)
		}
	}
	return Profile{Label: p.Label, Args: args}
}

// SupportedProfiles also returns CLI-adapted profiles, so a profile that
// passes capability checks is the same one later given to the process.
func SupportedProfiles(profiles []Profile, help string) []Profile {
	known := DocumentedOptions(help)
	var supported []Profile
	for _, original := range profiles {
		p := adaptProfileFlags(original, known)
		ok := true
		for _, arg := range p.Args {
			if strings.HasPrefix(arg, "--") {
				name, _, _ := strings.Cut(arg, "=")
				if !known[name] {
					ok = false
					break
				}
			}
		}
		if ok {
			supported = append(supported, p)
		}
	}
	return supported
}
