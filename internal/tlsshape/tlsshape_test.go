package tlsshape

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
)

func localTLSServer(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gateway"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"h2"},
		// Like WARP's gateway: a client certificate is demanded.
		ClientAuth: tls.RequireAnyClientCert})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	return l.Addr().String()
}

// Every fingerprint and fragment form completes a real handshake, so a
// timeout on a live network is the network, not the hello.
func TestProbeShapesHandshake(t *testing.T) {
	addr := localTLSServer(t)
	for _, f := range Fingerprints {
		for _, frag := range []string{NoFragment, DefaultFragment, "1-3/0-1", "100-200/0-5", ExitNodeMask} {
			if _, err := Probe(context.Background(), addr, Shape{DefaultSNI, f.Name, frag}); err != nil {
				t.Errorf("%s %s: %v", f.Name, frag, err)
			}
		}
	}
}

func TestOptions(t *testing.T) {
	o, err := ParseOptions("", " Semi-Python ", "")
	if err == nil {
		t.Fatalf("a fingerprint name is not a server name: %+v", o)
	}
	o, err = ParseOptions(" Semi-Python ", "", "")
	if err != nil || o.Fingerprint != SemiPython || o.SNI != Auto || o.Fragment != Auto {
		t.Fatalf("%+v %v", o, err)
	}
	for _, bad := range [][3]string{{"safari", "", ""}, {"", "1.2.3.4", ""}, {"", "https://x.com", ""}, {"", "", "8-16"}, {"", "", "0/1"}, {"", "", "20-10/1"}} {
		if _, err := ParseOptions(bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if o, err := ParseOptions("", "A.example.com., b.example.com", "off"); err != nil || o.SNI != "a.example.com,b.example.com" || o.Fragment != "off" {
		t.Fatalf("%+v %v", o, err)
	}
}

// PattNG's AetherFingerprint arguments, exactly.
func TestFingerprintArgs(t *testing.T) {
	sp, _ := FingerprintByName(SemiPython)
	if got := strings.Join(sp.Args(), " "); !strings.HasPrefix(got, "--tls-ciphers ECDHE-ECDSA-AES256-GCM-SHA384:") || !strings.HasSuffix(got, " --disable-grease") {
		t.Fatal(got)
	}
	if c, _ := FingerprintByName(Chrome); c.Args() != nil {
		t.Fatal("Chrome is the core default and adds nothing")
	}
	for _, f := range Fingerprints {
		if n := len(strings.Split(f.Ciphers, ":")); f.Name != Chrome && n != len(f.ids) {
			t.Errorf("%s: %d names, %d ids", f.Name, n, len(f.ids))
		}
	}
}

func fakeProbe(pass func(Shape) bool) ProbeFunc {
	return func(_ context.Context, _ string, s Shape) (time.Duration, error) {
		if pass(s) {
			return 100 * time.Millisecond, nil
		}
		return 0, errors.New("timeout")
	}
}

func TestCalibrateChoosesWhatPasses(t *testing.T) {
	o, _ := ParseOptions("", "", "")
	r := Calibrate(context.Background(), o, Config{Gateways: []string{"g1"}, Probe: fakeProbe(func(s Shape) bool {
		return s.SNI != DefaultSNI && s.Fragment != DefaultFragment
	})})
	if r.SNI == "" || r.SNI == DefaultSNI || r.Fingerprint != Chrome || r.AltFingerprint != SemiPython || r.Fragment == DefaultFragment || r.Fragment == "" {
		t.Fatalf("%+v", r)
	}
	// Only the cut hello passes: the names are measured again with the mask.
	r = Calibrate(context.Background(), o, Config{Gateways: []string{"g1"}, Probe: fakeProbe(func(s Shape) bool {
		return s.Fragment == ExitNodeMask
	})})
	if r.SNI != DefaultSNI || !r.Reached() {
		t.Fatalf("name not found through the mask: %+v", r)
	}
	// Fixed choices are measured, not replaced.
	o, _ = ParseOptions("go", "a.example.com", "off")
	r = Calibrate(context.Background(), o, Config{Gateways: []string{"g1"}, Probe: fakeProbe(func(Shape) bool { return true })})
	for _, tr := range r.Trials {
		if tr.Fingerprint != Go || tr.SNI != "a.example.com" || tr.Fragment != NoFragment {
			t.Fatalf("fixed choice not honored: %+v", tr)
		}
	}
}

func TestReachableGatewaysSkipsRefused(t *testing.T) {
	addr := localTLSServer(t)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l.Addr().String()
	l.Close()
	if got := ReachableGateways(context.Background(), []string{closed, addr}, 2); len(got) != 1 || got[0] != addr {
		t.Fatal(got)
	}
}

func TestApplyAndOrder(t *testing.T) {
	profiles, err := aether.ParseProfiles(aether.DefaultProfiles, "ECH", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	auto, _ := ParseOptions("", "", "")
	r := &Result{SNI: "speed.cloudflare.com", Fingerprint: Chrome, AltFingerprint: Go, Fragment: "100-200/0-5", Gateways: []string{"g"}}
	shaped := Apply(profiles, auto, r)
	var twin, fragmented *aether.Profile
	for i, p := range shaped {
		if p.Label == "WARP, MASQUE over HTTP/2, F&F go" {
			twin = &shaped[i]
		}
		if p.Label == "WARP, MASQUE over HTTP/2, fragmented" {
			fragmented = &shaped[i]
		}
		if p.Method() == "masque-h2" && !p.Has("--ech") && p.Value("--masque-sni") != "speed.cloudflare.com" {
			t.Errorf("%s: measured name not applied", p.Label)
		}
		if p.Has("--ech") && p.Has("--masque-sni") {
			t.Errorf("%s: ECH hides the name; --masque-sni would change only the inner one", p.Label)
		}
	}
	if twin == nil || twin.Value("--tls-ciphers") == "" || !twin.Has("--disable-grease") {
		t.Fatalf("no F&F twin: %+v", twin)
	}
	if fragmented == nil || fragmented.Value("--fragment-size") != "100-200" || fragmented.Value("--fragment-delay") != "0-5" {
		t.Fatalf("measured fragment range not applied: %+v", fragmented)
	}
	// Exit-node twins drop Aether's own fragment ranges with the flag.
	for _, p := range aether.WithExitNodes(shaped) {
		if p.ExitNode() != "" && (p.Has("--fragment") || p.Has("--fragment-size") || p.Has("--fragment-delay")) {
			t.Fatalf("%s keeps Aether fragmentation under the exit-node mask", p.Label)
		}
	}

	// Measured: Chrome's whole hello fails, the F&F twin passes.
	r.Trials = []Trial{
		{Shape: Shape{"speed.cloudflare.com", Chrome, NoFragment}, Attempts: 2},
		{Shape: Shape{"speed.cloudflare.com", Go, NoFragment}, Attempts: 2, OK: 2, MS: 90},
	}
	ordered := Order(aether.WithExitNodes(Apply(profiles, auto, r)), r)
	if ordered[0].Label != "WARP, MASQUE over HTTP/2, F&F go" {
		t.Fatalf("passing twin not first: %s", ordered[0].Label)
	}
	at := map[string]int{}
	for i, p := range ordered {
		at[p.Label] = i
	}
	// MASQUE and MASQUE-in-MASQUE H2 send the same failing hello: both go
	// after the profiles the calibration does not model, such as HTTP/3.
	if at["WARP, MASQUE over HTTP/2"] < at["WARP, MASQUE over HTTP/3"] || at["WARP, MASQUE-in-MASQUE H2"] < at["WARP, MASQUE over HTTP/3"] {
		t.Fatalf("failing hello not after unmeasured profiles: %v", at)
	}

	// A fixed fingerprint applies to every MASQUE profile, H3 too, and adds
	// no twin; fragment off removes Aether's fragmentation.
	fixed, _ := ParseOptions("semi-python", "x.example.com", "off")
	for _, p := range Apply(profiles, fixed, nil) {
		if strings.Contains(p.Label, "F&F") || p.Has("--fragment") {
			t.Fatalf("%s: fixed options must not add twins or keep fragmentation", p.Label)
		}
		if (p.Method() == "masque-h3" || p.Method() == "masque-h2") && p.Value("--tls-ciphers") == "" {
			t.Fatalf("%s: fixed fingerprint missing", p.Label)
		}
	}
	if Apply(profiles, fixed, nil)[0].Value("--masque-sni") != "x.example.com" {
		t.Fatal("fixed SNI missing")
	}
}

// The tuned name and fragment ranges do not change a profile's identity, so
// its per-network history survives a new calibration.
func TestTunedValuesKeepProfileID(t *testing.T) {
	a := aether.Profile{Label: "x", Args: []string{"--masque", "--h2", "--fragment", "--masque-sni", "a.example.com", "--fragment-size", "1-3", "--fragment-delay", "0-1"}}
	b := aether.Profile{Label: "x", Args: []string{"--masque", "--h2", "--fragment", "--masque-sni", "b.example.com", "--fragment-size", "100-200", "--fragment-delay", "0-5"}}
	if a.ID() != b.ID() {
		t.Fatal("tuned values changed the profile ID")
	}
}

func TestCandidatesFromLastConnection(t *testing.T) {
	path := t.TempDir() + "/masque-lastconn.toml"
	text := "peer = \"162.159.198.77:443\"\nrecent = [\"162.159.198.8:443\", \"10.0.0.1:2408\"]\n"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	got := CandidatesFrom(path)
	if got[0] != "162.159.198.77:443" || got[1] != "162.159.198.8:443" || len(got) != len(Gateways)+1 {
		t.Fatal(got)
	}
}
