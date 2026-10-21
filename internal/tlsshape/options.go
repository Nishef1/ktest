package tlsshape

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Auto lets the measurement decide.
const Auto = "auto"

// DefaultSNI is the core's own --masque-sni default (Aether, PattNG).
const DefaultSNI = "www.cloudflare.com"

// DefaultFragment is the core's own --fragment-size/--fragment-delay.
const DefaultFragment = "8-16/2-10"

// SNICandidates are tried when the name is left to the measurement. The
// MASQUE gateway does not check the name; the network's filter may, so only
// names that look like ordinary Cloudflare traffic are offered.
var SNICandidates = []string{DefaultSNI, "cloudflare.com", "one.one.one.one", "speed.cloudflare.com", "developers.cloudflare.com", "blog.cloudflare.com"}

// FragmentCandidates are Aether --fragment ranges, "size/delay" in bytes and
// milliseconds, tried when the range is left to the measurement.
var FragmentCandidates = []string{DefaultFragment, "1-3/1-3", "3-8/5-15", "16-32/2-10", "40-80/10-30", "100-200/0-5"}

// Options are the user's choices. Each is Auto unless the user set it.
type Options struct {
	// Fingerprint: auto, chrome, firefox, semi-python or go.
	Fingerprint string
	// SNI: auto, a server name, or comma-separated names to measure among.
	SNI string
	// Fragment: auto, off, or "size/delay" such as 8-16/2-10.
	Fragment string
}

// ParseOptions validates and normalizes the three choices; "" means auto.
func ParseOptions(fingerprint, sni, fragment string) (Options, error) {
	o := Options{Fingerprint: norm(fingerprint), SNI: norm(sni), Fragment: norm(fragment)}
	if o.Fingerprint != Auto {
		if _, ok := FingerprintByName(o.Fingerprint); !ok {
			return Options{}, fmt.Errorf("TLS fingerprint %q: use auto, chrome, firefox, semi-python or go", fingerprint)
		}
	}
	if o.SNI != Auto {
		names, err := ParseSNIs(o.SNI)
		if err != nil {
			return Options{}, err
		}
		o.SNI = strings.Join(names, ",")
	}
	if o.Fragment != Auto && o.Fragment != "off" {
		if _, _, err := ParseFragment(o.Fragment); err != nil {
			return Options{}, err
		}
	}
	return o, nil
}

func norm(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return Auto
	}
	return s
}

// ParseSNIs reads a comma-separated list of server names. Aether refuses an
// IP address or a malformed name at start, so they are refused here first.
func ParseSNIs(text string) ([]string, error) {
	var names []string
	seen := map[string]bool{}
	for _, name := range strings.Split(text, ",") {
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if name == "" {
			continue
		}
		if !validName(name) {
			return nil, fmt.Errorf("MASQUE SNI %q is not a server name (no IP addresses, schemes or ports)", name)
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, errors.New("MASQUE SNI: give a server name, a comma-separated list, or auto")
	}
	if len(names) > 12 {
		return nil, errors.New("MASQUE SNI: at most 12 names")
	}
	return names, nil
}

func validName(name string) bool {
	if len(name) > 253 || net.ParseIP(name) != nil || !strings.Contains(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Range is an inclusive "n" or "a-b".
type Range struct{ Min, Max int }

func (r Range) String() string {
	if r.Min == r.Max {
		return strconv.Itoa(r.Min)
	}
	return strconv.Itoa(r.Min) + "-" + strconv.Itoa(r.Max)
}

func parseRange(text string, low, high int) (Range, error) {
	a, b, found := strings.Cut(strings.TrimSpace(text), "-")
	min, err := strconv.Atoi(strings.TrimSpace(a))
	if err != nil {
		return Range{}, fmt.Errorf("range %q", text)
	}
	max := min
	if found {
		if max, err = strconv.Atoi(strings.TrimSpace(b)); err != nil {
			return Range{}, fmt.Errorf("range %q", text)
		}
	}
	if min > max || min < low || max > high {
		return Range{}, fmt.Errorf("range %q must be within %d-%d, low to high", text, low, high)
	}
	return Range{min, max}, nil
}

// ParseFragment reads "size/delay": a chunk size of 1-1000 bytes and a delay
// of 0-1000 ms between chunks, each "n" or "a-b".
func ParseFragment(text string) (size, delay Range, err error) {
	s, d, ok := strings.Cut(text, "/")
	if !ok {
		return Range{}, Range{}, fmt.Errorf("fragment %q: want size/delay such as %s, auto or off", text, DefaultFragment)
	}
	if size, err = parseRange(s, 1, 1000); err != nil {
		return Range{}, Range{}, fmt.Errorf("fragment size: %w", err)
	}
	if delay, err = parseRange(d, 0, 1000); err != nil {
		return Range{}, Range{}, fmt.Errorf("fragment delay: %w", err)
	}
	return size, delay, nil
}

// Key identifies the choices a calibration was made for.
func (o Options) Key() string { return o.Fingerprint + "|" + o.SNI + "|" + o.Fragment }

// Summary is a short human description.
func (o Options) Summary() string {
	return "fingerprint " + o.Fingerprint + " · MASQUE SNI " + o.SNI + " · fragment " + o.Fragment
}
