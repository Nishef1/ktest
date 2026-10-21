package tlsshape

import (
	"sort"
	"strings"

	"github.com/Nishef1/ktest/internal/aether"
)

func overMasque(p aether.Profile) bool {
	if p.Psiphon() || p.Has("--tor-only") || p.Has("--tor") || p.Has("--psiphon") || p.Has("--tor-reverse") || p.Has("--psiphon-reverse") {
		return false
	}
	return aether.UsesMASQUE(p.Method())
}

// chosenSNI is the name the profiles carry: the user's single name, else the
// measured best of the user's list or of the built-in candidates, else the
// first of the user's list; "" leaves the core's default.
func chosenSNI(o Options, r *Result) string {
	if o.SNI != Auto && !strings.Contains(o.SNI, ",") {
		return o.SNI
	}
	if r != nil && r.SNI != "" {
		return r.SNI
	}
	if o.SNI != Auto {
		names, _ := ParseSNIs(o.SNI)
		return names[0]
	}
	return ""
}

// Apply gives Aether's MASQUE profiles the chosen server name, fragment range
// and fingerprint. With the fingerprint left to auto, every direct MASQUE
// HTTP/2 profile keeps the core's Chrome hello and gains an F&F twin with the
// measured best other fingerprint (Patterniha's semi-python when nothing was
// measured); WithExitNodes then gives the twin the tlshello-0-len mask, which
// is F&F exactly as Patterniha publishes it for MASQUE H2. ECH profiles keep
// their name: with ECH the visible name is the ECH key's, not --masque-sni.
func Apply(profiles []aether.Profile, o Options, r *Result) []aether.Profile {
	sni := chosenSNI(o, r)
	fixed, _ := FingerprintByName(o.Fingerprint)
	alt := SemiPython
	if r != nil && r.AltFingerprint != "" {
		alt = r.AltFingerprint
	}
	altFP, _ := FingerprintByName(alt)
	var out []aether.Profile
	seen := map[string]bool{}
	emit := func(p aether.Profile) {
		key := strings.Join(p.Args, "\x00")
		if !seen[key] {
			seen[key] = true
			out = append(out, p)
		}
	}
	for _, p := range profiles {
		if !overMasque(p) {
			emit(p)
			continue
		}
		q := aether.Profile{Label: p.Label, Args: append([]string(nil), p.Args...)}
		if sni != "" && sni != DefaultSNI && !q.Has("--ech") && !q.Has("--masque-sni") {
			q.Args = append(q.Args, "--masque-sni", sni)
		}
		if q.Has("--fragment") && !q.Has("--fragment-size") && !q.Has("--fragment-delay") {
			fragment := ""
			switch o.Fragment {
			case "off":
				q.Args = without(q.Args, "--fragment")
			case Auto:
				if r != nil && r.Fragment != DefaultFragment {
					fragment = r.Fragment
				}
			default:
				fragment = o.Fragment
			}
			if size, delay, err := ParseFragment(fragment); err == nil {
				q.Args = append(q.Args, "--fragment-size", size.String(), "--fragment-delay", delay.String())
			}
		}
		if q.Has("--tls-ciphers") {
			emit(q)
			continue
		}
		if o.Fingerprint != Auto {
			q.Args = append(q.Args, fixed.Args()...)
			emit(q)
			continue
		}
		if q.Method() != "masque-h2" || q.Has("--ech") || q.Has("--upstream") {
			emit(q)
			continue
		}
		twin := aether.Profile{Label: q.Label + ", F&F " + altFP.Name, Args: append(append([]string(nil), q.Args...), altFP.Args()...)}
		// The network answered the twin and not Chrome: try the twin first.
		if r != nil && predict(*r, q) == predictFail && predict(*r, twin) == predictPass {
			emit(twin)
			emit(q)
		} else {
			emit(q)
			emit(twin)
		}
	}
	return out
}

func without(args []string, flag string) []string {
	var out []string
	for _, a := range args {
		if a != flag {
			out = append(out, a)
		}
	}
	return out
}

const (
	predictUnknown = iota
	predictPass
	predictFail
)

// shapeOf is the measured shape a profile's MASQUE hello would have, or false
// when the calibration does not model it (HTTP/3, ECH, KTest's own carrier).
func shapeOf(p aether.Profile) (Shape, bool) {
	switch p.Method() {
	case "masque-h2", "gool-h2", "mim-h2":
	default:
		return Shape{}, false
	}
	if !overMasque(p) || p.Has("--ech") || p.LocalCarrier() || (p.Has("--upstream") && p.ExitNode() == "") {
		return Shape{}, false
	}
	s := Shape{SNI: DefaultSNI, Fingerprint: fingerprintOfArgs(p.Value("--tls-ciphers")), Fragment: NoFragment}
	if v := p.Value("--masque-sni"); v != "" {
		s.SNI = v
	}
	switch {
	case p.ExitNode() != "":
		s.Fragment = p.ExitNode()
	case p.Has("--fragment"):
		size, delay := p.Value("--fragment-size"), p.Value("--fragment-delay")
		def := strings.Split(DefaultFragment, "/")
		if size == "" {
			size = def[0]
		}
		if delay == "" {
			delay = def[1]
		}
		s.Fragment = size + "/" + delay
	}
	return s, true
}

func predict(r Result, p aether.Profile) int {
	s, ok := shapeOf(p)
	if !ok {
		return predictUnknown
	}
	t, ok := r.Lookup(s)
	switch {
	case !ok || t.Attempts == 0:
		return predictUnknown
	case t.OK > 0:
		return predictPass
	}
	return predictFail
}

// Order puts the profiles whose hello this network answered first, those it
// did not last, and keeps every other order. Per-network measurements of real
// tunnels are applied after this and override it.
func Order(profiles []aether.Profile, r *Result) []aether.Profile {
	if r == nil || !r.Reached() {
		return profiles
	}
	out := append([]aether.Profile(nil), profiles...)
	rank := func(p aether.Profile) int {
		switch predict(*r, p) {
		case predictPass:
			return 0
		case predictFail:
			return 2
		}
		return 1
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })
	return out
}

// Prediction describes what the calibration says of a profile, for display.
func Prediction(r *Result, p aether.Profile) string {
	if r == nil {
		return ""
	}
	switch predict(*r, p) {
	case predictPass:
		return "hello passed calibration"
	case predictFail:
		return "hello failed calibration"
	}
	return ""
}
