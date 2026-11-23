package tlsshape

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/Nishef1/ktest/internal/aether"
)

// Winner returns an actually measured combination, not independent marginal winners.
func Winner(r *Result, o Options) (Trial, bool) {
	if r == nil || r.Options != o.Key() {
		return Trial{}, false
	}
	var best Trial
	found := false
	for _, t := range r.Trials {
		if t.OK <= 0 || t.Attempts <= 0 || t.OK > t.Attempts || t.MS < 0 {
			continue
		}
		if _, ok := FingerprintByName(t.Fingerprint); !ok || !validName(t.SNI) {
			continue
		}
		if o.Fingerprint != Auto && t.Fingerprint != o.Fingerprint {
			continue
		}
		if o.SNI != Auto {
			names, err := ParseSNIs(o.SNI)
			if err != nil {
				continue
			}
			allowed := false
			for _, name := range names {
				allowed = allowed || name == t.SNI
			}
			if !allowed {
				continue
			}
		}
		switch o.Fragment {
		case "off":
			if t.Fragment != NoFragment {
				continue
			}
		case Auto:
			if t.Fragment != NoFragment && t.Fragment != ExitNodeMask {
				if _, _, err := ParseFragment(t.Fragment); err != nil {
					continue
				}
			}
		default:
			if t.Fragment != o.Fragment {
				continue
			}
		}
		if !found || betterTrial(t, best) {
			best, found = t, true
		}
	}
	return best, found
}

func betterTrial(a, b Trial) bool {
	if a.OK != b.OK {
		return a.OK > b.OK
	}
	if a.Attempts != b.Attempts {
		return a.Attempts < b.Attempts
	}
	return a.MS < b.MS
}

// measuredProfile constructs the exact combination for a compatible direct H2
// profile. The session owner supplies the exit-node if the measured mask won.
func measuredProfile(p aether.Profile, t Trial) (aether.Profile, bool) {
	if p.Method() != "masque-h2" || !overMasque(p) || p.Has("--ech") ||
		p.Has("--upstream") || p.Has("--tls-ciphers") || p.Has("--disable-grease") {
		return aether.Profile{}, false
	}
	q := aether.Profile{Label: p.Label + ", measured " + t.Fingerprint}
	for i := 0; i < len(p.Args); i++ {
		name, _, inline := strings.Cut(p.Args[i], "=")
		switch name {
		case "--fragment", "--no-fragment":
			continue
		case "--fragment-size", "--fragment-delay", "--masque-sni":
			if !inline {
				i++
			}
			continue
		}
		q.Args = append(q.Args, p.Args[i])
	}
	if t.SNI != DefaultSNI {
		q.Args = append(q.Args, "--masque-sni", t.SNI)
	}
	fp, _ := FingerprintByName(t.Fingerprint)
	q.Args = append(q.Args, fp.Args()...)
	switch t.Fragment {
	case NoFragment:
	case ExitNodeMask:
		q.Args = append(q.Args, "--upstream", aether.ExitNodeURL(ExitNodeMask))
	default:
		size, delay, err := ParseFragment(t.Fragment)
		if err != nil {
			return aether.Profile{}, false
		}
		q.Args = append(q.Args, "--fragment", "--fragment-size", size.String(), "--fragment-delay", delay.String())
	}
	return q, true
}

// ActiveSummary describes configured runtime options, not an old test result.
func ActiveSummary(p aether.Profile) string {
	if !overMasque(p) {
		return ""
	}
	fp := fingerprintOfArgs(p.Value("--tls-ciphers"))
	name := p.Value("--masque-sni")
	if name == "" {
		name = DefaultSNI
	}
	if p.Has("--ech") {
		name = "ECH (outer name differs)"
	}
	fragment := NoFragment
	if p.ExitNode() != "" {
		fragment = p.ExitNode()
	} else if p.LocalCarrier() {
		fragment = "local carrier"
	} else if p.Has("--fragment") {
		size, delay := p.Value("--fragment-size"), p.Value("--fragment-delay")
		if size == "" {
			size = strings.Split(DefaultFragment, "/")[0]
		}
		if delay == "" {
			delay = strings.Split(DefaultFragment, "/")[1]
		}
		fragment = size + "/" + delay
	}
	return fp + " · SNI " + name + " · fragment " + fragment
}

// HistoryKey retains stable core/profile identity while refusing to reuse
// performance evidence collected under a different explicit SNI or fragment.
func HistoryKey(p aether.Profile) string {
	if !p.Has("--masque-sni") && !p.Has("--fragment-size") && !p.Has("--fragment-delay") {
		return p.ID()
	}
	sum := sha256.Sum256([]byte(p.ID() + "\x00" + p.Value("--masque-sni") + "\x00" +
		p.Value("--fragment-size") + "\x00" + p.Value("--fragment-delay")))
	return fmt.Sprintf("%x", sum[:16])
}

// The -6 flag selects the outer carrier family, independently of application
// destination policy. Never credit an IPv6 profile with IPv4 measurements.
func resultForProfile(r *Result, p aether.Profile) *Result {
	if r == nil {
		return nil
	}
	if p.Has("-6") {
		return r.IPv6
	}
	return r
}
