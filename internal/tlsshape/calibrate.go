package tlsshape

import (
	"context"
	"errors"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/exitnode"
	utls "github.com/refraction-networking/utls"
)

// Gateways are WARP's MASQUE-over-HTTP/2 gateways (TCP 443) tried when the
// core has none of its own to offer, spread over the range Aether found
// working on a filtered Iranian ISP on 2026-10-20/21 (where .1 itself was
// unreachable while .8, .23 and .32 answered).
var Gateways = []string{"162.159.198.8:443", "162.159.198.23:443", "162.159.198.32:443", "162.159.198.189:443",
	"162.159.198.249:443", "162.159.198.1:443", "162.159.198.2:443", "162.159.198.64:443", "162.159.198.100:443", "162.159.198.150:443"}

var gatewayPattern = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}:443\b`)

// CandidatesFrom lists the HTTP/2 gateways named in the core's last-connection
// file (masque-lastconn.toml: the peer and its recent ones), then Gateways.
func CandidatesFrom(lastConn string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(addr string) {
		if !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
	}
	if data, err := os.ReadFile(lastConn); err == nil && len(data) < 64<<10 {
		for _, addr := range gatewayPattern.FindAllString(string(data), 16) {
			add(addr)
		}
	}
	for _, addr := range Gateways {
		add(addr)
	}
	return out
}

// ReachableGateways connects to the candidates in parallel over plain TCP and
// returns up to want of them that accepted, in candidate order. A hello can
// only be measured against an address the network lets through at all.
func ReachableGateways(ctx context.Context, candidates []string, want int) []string {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ok := make([]bool, len(candidates))
	var wg sync.WaitGroup
	for i, addr := range candidates {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var d net.Dialer
			if c, err := d.DialContext(ctx, "tcp", addr); err == nil {
				c.Close()
				ok[i] = true
			}
		}()
	}
	wg.Wait()
	var out []string
	for i, addr := range candidates {
		if ok[i] && len(out) < want {
			out = append(out, addr)
		}
	}
	return out
}

// NoFragment and the exit-node preset name are the non-range fragments.
const (
	NoFragment   = "none"
	ExitNodeMask = exitnode.PresetTLSHelloZero
)

// Shape is one way the MASQUE ClientHello leaves this machine.
type Shape struct {
	SNI         string `json:"sni"`
	Fingerprint string `json:"fingerprint"`
	// Fragment is NoFragment, ExitNodeMask, or an Aether "size/delay" range.
	Fragment string `json:"fragment"`
}

func (s Shape) String() string { return s.Fingerprint + " · " + s.SNI + " · " + s.Fragment }

// Trial is the outcome of one shape against the gateways.
type Trial struct {
	Shape
	Attempts int     `json:"attempts"`
	OK       int     `json:"ok"`
	MS       float64 `json:"ms,omitempty"`
	Failure  string  `json:"failure,omitempty"`
}

// Result is a calibration of one network for one set of options. Its choices
// are the best measured value of each axis; "" means none passed.
type Result struct {
	Options     string    `json:"options"`
	Checked     time.Time `json:"checked"`
	SNI         string    `json:"sni,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	// AltFingerprint is the best non-Chrome fingerprint: the F&F variant.
	AltFingerprint string `json:"alt_fingerprint,omitempty"`
	// Fragment is the best Aether --fragment range, "size/delay".
	Fragment string `json:"fragment,omitempty"`
	// Gateways are the addresses measured; none means TCP itself was refused.
	Gateways []string `json:"gateways,omitempty"`
	Trials   []Trial  `json:"trials"`
}

// Reached reports whether any shape completed a handshake.
func (r Result) Reached() bool {
	for _, t := range r.Trials {
		if t.OK > 0 {
			return true
		}
	}
	return false
}

// Lookup finds the trial of a shape.
func (r Result) Lookup(s Shape) (Trial, bool) {
	for _, t := range r.Trials {
		if t.Shape == s {
			return t, true
		}
	}
	return Trial{}, false
}

// ProbeFunc runs one handshake of a shape against a gateway.
type ProbeFunc func(ctx context.Context, gateway string, s Shape) (time.Duration, error)

// Config is how a calibration reaches the network.
type Config struct {
	// Gateways are measured as given; Candidates (default Gateways) are
	// first checked for a TCP answer when Gateways is empty.
	Gateways   []string
	Candidates []string
	Probe      ProbeFunc
	// Progress, when set, is told each finished trial.
	Progress func(Trial)
}

// Calibrate measures, on this network, which server name, fingerprint and
// fragment let the MASQUE ClientHello through. It honors the user's fixed
// choices and measures only what was left to it. Three short stages, each in
// parallel: names (with the default ClientHello), then fingerprints with the
// best name, then fragments with both. A handshake counts once the gateway
// answered it, including a refusal of the missing client certificate: that is
// the gateway itself, past the filter.
func Calibrate(ctx context.Context, o Options, c Config) Result {
	r := Result{Options: o.Key(), Checked: time.Now()}
	if len(c.Gateways) == 0 {
		candidates := c.Candidates
		if len(candidates) == 0 {
			candidates = Gateways
		}
		c.Gateways = ReachableGateways(ctx, candidates, 2)
	}
	r.Gateways = c.Gateways
	if len(c.Gateways) == 0 {
		return r
	}
	if c.Probe == nil {
		c.Probe = Probe
	}
	run := func(shapes []Shape) []Trial {
		trials := make([]Trial, len(shapes))
		var wg sync.WaitGroup
		limit := make(chan struct{}, 8)
		for i, s := range shapes {
			wg.Add(1)
			go func() {
				defer wg.Done()
				trials[i] = trial(ctx, c, s, limit)
				if c.Progress != nil {
					c.Progress(trials[i])
				}
			}()
		}
		wg.Wait()
		r.Trials = append(r.Trials, trials...)
		return trials
	}

	names := SNICandidates
	if o.SNI != Auto {
		names, _ = ParseSNIs(o.SNI)
	}
	fp := Chrome
	if o.Fingerprint != Auto {
		fp = o.Fingerprint
	}
	baseFragment := NoFragment
	if o.Fragment != Auto && o.Fragment != "off" {
		baseFragment = o.Fragment
	}
	shapes := func(each []string, mk func(string) Shape) []Shape {
		var out []Shape
		for _, v := range each {
			out = append(out, mk(v))
		}
		return out
	}

	// 1. Names. When no name passes whole, the filter may be reading the
	// name itself: ask again with the exit-node's cut ClientHello.
	byName := run(shapes(names, func(n string) Shape { return Shape{n, fp, baseFragment} }))
	if best(byName, DefaultSNI, func(t Trial) string { return t.SNI }) == "" && baseFragment == NoFragment && o.Fragment != "off" && ctx.Err() == nil {
		byName = run(shapes(names, func(n string) Shape { return Shape{n, fp, ExitNodeMask} }))
		baseFragment = ExitNodeMask
	}
	r.SNI = best(byName, DefaultSNI, func(t Trial) string { return t.SNI })
	sni := r.SNI
	if sni == "" {
		sni = names[0]
	}

	// 2. Fingerprints, PattNG's four.
	if o.Fingerprint == Auto && ctx.Err() == nil {
		var all []string
		for _, f := range Fingerprints {
			all = append(all, f.Name)
		}
		byFP := run(shapes(all, func(f string) Shape { return Shape{sni, f, baseFragment} }))
		r.Fingerprint = best(byFP, Chrome, func(t Trial) string { return t.Fingerprint })
		var alts []Trial
		for _, t := range byFP {
			if t.Fingerprint != Chrome {
				alts = append(alts, t)
			}
		}
		r.AltFingerprint = best(alts, SemiPython, func(t Trial) string { return t.Fingerprint })
	} else if t, ok := r.Lookup(Shape{sni, fp, baseFragment}); ok && t.OK > 0 {
		r.Fingerprint = fp
	}
	if r.Fingerprint != "" {
		fp = r.Fingerprint
	}

	// 3. Fragments: Aether's ranges and the exit-node's tlshello-0-len.
	switch {
	case o.Fragment == Auto && ctx.Err() == nil:
		candidates := append(append([]string(nil), FragmentCandidates...), ExitNodeMask)
		byFragment := run(shapes(candidates, func(f string) Shape { return Shape{sni, fp, f} }))
		var ranges []Trial
		for _, t := range byFragment {
			if t.Fragment != ExitNodeMask {
				ranges = append(ranges, t)
			}
		}
		r.Fragment = best(ranges, DefaultFragment, func(t Trial) string { return t.Fragment })
		// F&F as Patterniha gives it for MASQUE H2: semi-python and the
		// exit-node mask together, measured even when another won.
		if fp != SemiPython && o.Fingerprint == Auto {
			run([]Shape{{sni, SemiPython, ExitNodeMask}})
		}
	case o.Fragment != Auto && o.Fragment != "off" && ctx.Err() == nil:
		if t, ok := r.Lookup(Shape{sni, fp, o.Fragment}); !ok {
			run([]Shape{{sni, fp, o.Fragment}})
		} else if t.OK > 0 {
			r.Fragment = o.Fragment
		}
		if t, ok := r.Lookup(Shape{sni, fp, o.Fragment}); ok && t.OK > 0 {
			r.Fragment = o.Fragment
		}
	}
	return r
}

// best picks the value whose trials passed most often, then fastest; the
// preferred value wins a tie on passes when it is within 25% of the fastest.
func best(trials []Trial, preferred string, key func(Trial) string) string {
	ok := make([]Trial, 0, len(trials))
	for _, t := range trials {
		if t.OK > 0 {
			ok = append(ok, t)
		}
	}
	if len(ok) == 0 {
		return ""
	}
	sort.SliceStable(ok, func(i, j int) bool {
		if ok[i].OK != ok[j].OK {
			return ok[i].OK > ok[j].OK
		}
		return ok[i].MS < ok[j].MS
	})
	for _, t := range ok {
		if t.OK == ok[0].OK && key(t) == preferred && t.MS <= ok[0].MS*1.25 {
			return preferred
		}
	}
	return key(ok[0])
}

func trial(ctx context.Context, c Config, s Shape, limit chan struct{}) Trial {
	t := Trial{Shape: s}
	var total time.Duration
	var failures []string
	for _, gw := range c.Gateways {
		select {
		case limit <- struct{}{}:
		case <-ctx.Done():
			t.Failure = "cancelled"
			return t
		}
		d, err := c.Probe(ctx, gw, s)
		<-limit
		t.Attempts++
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		t.OK++
		total += d
	}
	if t.OK > 0 {
		t.MS = float64(total.Milliseconds()) / float64(t.OK)
	}
	if t.OK < t.Attempts && len(failures) > 0 {
		t.Failure = failures[0]
	}
	return t
}

// ProbeTimeout bounds one handshake, fragment delays included.
const ProbeTimeout = 6 * time.Second

// Probe dials a gateway directly and runs the MASQUE ClientHello of a shape:
// the fingerprint's TLS 1.2 suites after BoringSSL's TLS 1.3 ones, GREASE as
// the fingerprint has it, Aether's groups (P-256 first, with its key share)
// and ALPN h2, cut as the fragment says. It is a close model of the core's
// ClientHello, not its bytes; a live tunnel still decides which profile wins.
func Probe(ctx context.Context, gateway string, s Shape) (time.Duration, error) {
	f, ok := FingerprintByName(s.Fingerprint)
	if !ok {
		return 0, errors.New("unknown fingerprint")
	}
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	start := time.Now()
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", gateway)
	if err != nil {
		return 0, err
	}
	defer raw.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	conn := raw
	switch s.Fragment {
	case NoFragment, "":
	case ExitNodeMask, exitnode.PresetTLSHello:
		mask, err := exitnode.Preset(s.Fragment)
		if err != nil {
			return 0, err
		}
		conn = mask.WrapTCP(raw)
	default:
		size, delay, err := ParseFragment(s.Fragment)
		if err != nil {
			return 0, err
		}
		conn = &chunkConn{Conn: raw, size: size, delay: delay}
	}
	u := utls.UClient(conn, &utls.Config{ServerName: s.SNI, InsecureSkipVerify: true, NextProtos: []string{"h2"}}, utls.HelloCustom)
	spec, err := helloSpec(f)
	if err != nil {
		return 0, err
	}
	if err := u.ApplyPreset(&spec); err != nil {
		return 0, err
	}
	if err := u.HandshakeContext(ctx); err != nil && !gatewayAnswered(err) {
		return 0, shortError(err)
	}
	return time.Since(start), nil
}

// gatewayAnswered: WARP's gateway asks for the client certificate the
// registered key would give; refusing its absence proves the hello arrived.
func gatewayAnswered(err error) bool {
	text := err.Error()
	if !strings.Contains(text, "remote error: tls: ") {
		return false
	}
	for _, alert := range []string{"certificate required", "access denied", "bad certificate", "unknown certificate", "certificate unknown", "unsupported certificate"} {
		if strings.Contains(text, alert) {
			return true
		}
	}
	return false
}

func shortError(err error) error {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return errors.New("timeout")
	case strings.Contains(err.Error(), "reset"):
		return errors.New("reset")
	case strings.Contains(err.Error(), "EOF"):
		return errors.New("closed")
	}
	return err
}

func helloSpec(f Fingerprint) (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		return spec, err
	}
	var suites []uint16
	if f.Grease {
		suites = append(suites, utls.GREASE_PLACEHOLDER)
	}
	suites = append(suites, utls.TLS_AES_128_GCM_SHA256, utls.TLS_AES_256_GCM_SHA384, utls.TLS_CHACHA20_POLY1305_SHA256)
	spec.CipherSuites = append(suites, f.ids...)
	grease := func(v []utls.CurveID, rest ...utls.CurveID) []utls.CurveID {
		if f.Grease {
			v = append(v, utls.CurveID(utls.GREASE_PLACEHOLDER))
		}
		return append(v, rest...)
	}
	var exts []utls.TLSExtension
	for _, ext := range spec.Extensions {
		switch x := ext.(type) {
		case *utls.UtlsGREASEExtension:
			if !f.Grease {
				continue
			}
		case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew,
			*utls.GREASEEncryptedClientHelloExtension, *utls.UtlsPreSharedKeyExtension:
			continue
		case *utls.SupportedCurvesExtension:
			x.Curves = grease(nil, utls.CurveP256, utls.X25519, utls.CurveP384)
		case *utls.KeyShareExtension:
			var shares []utls.KeyShare
			if f.Grease {
				shares = append(shares, utls.KeyShare{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}})
			}
			x.KeyShares = append(shares, utls.KeyShare{Group: utls.CurveP256})
		case *utls.SupportedVersionsExtension:
			var versions []uint16
			if f.Grease {
				versions = append(versions, utls.GREASE_PLACEHOLDER)
			}
			x.Versions = append(versions, utls.VersionTLS13, utls.VersionTLS12)
		case *utls.ALPNExtension:
			x.AlpnProtocols = []string{"h2"}
		}
		exts = append(exts, ext)
	}
	spec.Extensions = exts
	return spec, nil
}

// chunkConn is Aether's --fragment: the first flight goes out in chunks of
// a size in the range, with a delay in the range between them.
type chunkConn struct {
	net.Conn
	size, delay Range
	done        bool
}

func (c *chunkConn) Write(p []byte) (int, error) {
	if c.done {
		return c.Conn.Write(p)
	}
	c.done = true
	written := 0
	for written < len(p) {
		n := between(c.size)
		if written+n > len(p) {
			n = len(p) - written
		}
		m, err := c.Conn.Write(p[written : written+n])
		written += m
		if err != nil {
			return written, err
		}
		if written < len(p) {
			if ms := between(c.delay); ms > 0 {
				time.Sleep(time.Duration(ms) * time.Millisecond)
			}
		}
	}
	return written, nil
}

func between(r Range) int {
	if r.Max <= r.Min {
		return r.Min
	}
	return r.Min + int(time.Now().UnixNano()%int64(r.Max-r.Min+1))
}
