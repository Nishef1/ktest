package aether

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// LocalCarrierURL is resolved by the session owner, never by the native core.
// Keeping the placeholder in profile identity preserves learning across ports.
const LocalCarrierURL = "socks5://{LOCAL}"

func (p Profile) LocalCarrier() bool { return p.Value("--upstream") == LocalCarrierURL }

func CanCarryLocally(p Profile) bool {
	if p.Has("--upstream") || p.Has("--tor") || p.Has("--tor-reverse") || p.Has("--psiphon") || p.Has("--psiphon-reverse") {
		return false
	}
	switch p.Method() {
	case "masque-h2", "gool-h2", "mim-h2":
		return true
	}
	return false
}

// WithLocalCarriers retains direct transports and adds independent TCP
// attempts through our own Go/ByeDPI carrier. UDP transports stay direct.
func WithLocalCarriers(profiles []Profile) []Profile {
	var out []Profile
	remaining := 64 - len(profiles)
	for _, p := range profiles {
		out = append(out, p)
		standalone := !p.Has("--upstream") && (p.Psiphon() || p.Has("--tor-only"))
		if (!CanCarryLocally(p) && !standalone) || remaining <= 0 {
			continue
		}
		carried := Profile{Label: p.Label + " through local anti-DPI"}
		carried.Args = withoutFragment(p.Args)
		// The local proxy collects and shapes the complete first flight.
		carried.Args = append(carried.Args, "--no-fragment", "--upstream", LocalCarrierURL)
		out = append(out, carried)
		remaining--
	}
	return out
}

// exitNodePrefix starts the placeholder of PattNG's exit-node: the session
// owner starts an exitnode server with the named finalMask preset and binds
// its loopback address, exactly like the local carrier.
const exitNodePrefix = "socks5://{EXIT:"

// ExitNodeURL is the placeholder upstream for an exit-node preset.
func ExitNodeURL(preset string) string { return exitNodePrefix + preset + "}" }

// ExitNode is the exit-node preset this profile runs through, or "".
func (p Profile) ExitNode() string {
	preset, ok := strings.CutPrefix(p.Value("--upstream"), exitNodePrefix)
	if !ok {
		return ""
	}
	return strings.TrimSuffix(preset, "}")
}

// OwnedUpstream reports whether the profile's upstream is one KTest starts.
func (p Profile) OwnedUpstream() bool { return p.LocalCarrier() || p.ExitNode() != "" }

// ExitNodePreset is PattNG's finalMask preset for a WARP method: a TCP
// ClientHello mask for the HTTP/2 MASQUE families and UDP noise for every
// UDP transport. Psiphon, Tor and unknown methods get none.
func ExitNodePreset(method string) string {
	switch method {
	case "masque-h2", "gool-h2", "mim-h2":
		return "tlshello-0-len"
	case "masque-h3", "gool-h3", "mim-h3", "wireguard", "wiw":
		return "udp-noise"
	}
	return ""
}

// WithExitNodes adds, after each direct WARP profile, PattNG's way of running
// it: the same flags with --upstream through a loopback exit-node whose
// outgoing TCP/UDP carry PattNG's finalMask preset. The direct profile stays.
// Aether's own --fragment is dropped: in PattNG it is off unless asked for,
// and the exit-node shapes the complete first flight itself.
func WithExitNodes(profiles []Profile) []Profile {
	return WithExitNodesOptions(profiles, false)
}

// WithExitNodesOptions adds owned exit-node variants. When fragmentOff is true,
// TCP TLS-hello masks are excluded to honor the user's explicit fragmentation
// opt-out; UDP-noise variants remain because they are a distinct transport
// strategy, not TLS fragmentation.
func WithExitNodesOptions(profiles []Profile, fragmentOff bool) []Profile {
	var out []Profile
	remaining := 64 - len(profiles)
	for _, p := range profiles {
		out = append(out, p)
		preset := ExitNodePreset(p.Method())
		if preset == "" || (fragmentOff && preset == "tlshello-0-len") ||
			remaining <= 0 || p.Has("--upstream") || p.Psiphon() || p.Has("--tor-only") ||
			p.Has("--tor") || p.Has("--tor-reverse") || p.Has("--psiphon") || p.Has("--psiphon-reverse") {
			continue
		}
		node := Profile{Label: p.Label + " through PattNG exit-node (" + preset + ")"}
		node.Args = append(withoutFragment(p.Args), "--upstream", ExitNodeURL(preset))
		out = append(out, node)
		remaining--
	}
	return out
}

// BindLocalCarrier replaces the profile's owned upstream placeholder (local
// carrier or exit-node) with the loopback SOCKS address its owner started.
func BindLocalCarrier(args []string, address string) ([]string, error) {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("Aether local carrier requires an owned loopback SOCKS address")
	}
	out := append([]string(nil), args...)
	for i, arg := range out {
		value, inline := strings.CutPrefix(arg, "--upstream=")
		if value == LocalCarrierURL || (strings.HasPrefix(value, exitNodePrefix) && strings.HasSuffix(value, "}")) {
			if inline {
				out[i] = "--upstream=socks5://" + address
			} else {
				out[i] = "socks5://" + address
			}
		}
	}
	return out, nil
}

// withoutFragment drops Aether's own ClientHello fragmentation, with its
// size and delay ranges, where KTest's carrier shapes the first flight.
func withoutFragment(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		switch name, _, inline := strings.Cut(args[i], "="); name {
		case "--fragment", "--no-fragment":
			continue
		case "--fragment-size", "--fragment-delay":
			if !inline {
				i++
			}
			continue
		}
		out = append(out, args[i])
	}
	return out
}
