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
		for _, arg := range p.Args {
			if arg != "--fragment" && arg != "--no-fragment" {
				carried.Args = append(carried.Args, arg)
			}
		}
		// The local proxy collects and shapes the complete first flight.
		carried.Args = append(carried.Args, "--no-fragment", "--upstream", LocalCarrierURL)
		out = append(out, carried)
		remaining--
	}
	return out
}

func BindLocalCarrier(args []string, address string) ([]string, error) {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("Aether local carrier requires an owned loopback SOCKS address")
	}
	out := append([]string(nil), args...)
	for i, arg := range out {
		if arg == LocalCarrierURL {
			out[i] = "socks5://" + address
		}
		if strings.HasPrefix(arg, "--upstream="+LocalCarrierURL) {
			out[i] = "--upstream=socks5://" + address
		}
	}
	return out, nil
}
