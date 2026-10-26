package mobilebridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
	"github.com/Nishef1/ktest/internal/tlsshape"
)

// The Android "F&F and MASQUE SNI" settings: auto (measured per network) or
// a fixed value each. Read when a connection builds its Aether profiles.
var (
	aetherTLSMu   sync.Mutex
	aetherTLSOpts = tlsshape.Options{Fingerprint: tlsshape.Auto, SNI: tlsshape.Auto, Fragment: tlsshape.Auto}
)

// SetAetherTLS is called by the app before each connection; "" means auto.
// An invalid value is refused and the previous choice kept.
func SetAetherTLS(fingerprint, masqueSNI, fragment string) error {
	o, err := tlsshape.ParseOptions(fingerprint, masqueSNI, fragment)
	if err != nil {
		return err
	}
	aetherTLSMu.Lock()
	aetherTLSOpts = o
	aetherTLSMu.Unlock()
	return nil
}

func currentAetherTLS() tlsshape.Options {
	aetherTLSMu.Lock()
	defer aetherTLSMu.Unlock()
	return aetherTLSOpts
}

func tlsCalibrationPath(privateDir string) string {
	if privateDir == "" {
		return ""
	}
	return filepath.Join(privateDir, "aether", "tls-calibration.json")
}

func tlsNetworkKey() string {
	network := currentRouteNetworkToken()
	if network == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("ktest-tls-network:" + network))
	return hex.EncodeToString(sum[:16])
}

func tlsCalibrationConfig(privateDir string) tlsshape.Config {
	return tlsshape.Config{Candidates: tlsshape.CandidatesFrom(filepath.Join(privateDir, "aether", "masque-lastconn.toml"))}
}

// mobileTLSShape is the shape of a connection's profiles. With measure, a
// missing or stale calibration of this network is made (bounded); without,
// only a saved one is used.
func mobileTLSShape(ctx context.Context, privateDir string, measure bool) (tlsshape.Options, *tlsshape.Result) {
	o := currentAetherTLS()
	path, key := tlsCalibrationPath(privateDir), tlsNetworkKey()
	if r, ok := tlsshape.Cached(path, key, o); ok {
		return o, &r
	}
	if !measure || path == "" || key == "" {
		return o, nil
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if r, ok := tlsshape.Ensure(cctx, path, key, o, tlsCalibrationConfig(privateDir)); ok {
		return o, &r
	}
	return o, nil
}

// shapeProfiles applies the session's F&F and MASQUE name (before carriers).
func shapeProfiles(profiles []aether.Profile, o tlsshape.Options, r *tlsshape.Result) []aether.Profile {
	return tlsshape.Apply(profiles, o, r)
}

// A network that blocks every MASQUE gateway must not pay the entire
// calibration budget again on every Connect. Explicit Measure remains available.
var autoTLSMu sync.Mutex
var autoTLSRecent = map[string]time.Time{}

func allowAutoTLSProbe(network, options string, now time.Time) bool {
	if network == "" {
		return false
	}
	key := network + ":" + options
	autoTLSMu.Lock()
	defer autoTLSMu.Unlock()
	if when, found := autoTLSRecent[key]; found && now.Sub(when) < 10*time.Minute {
		return false
	}
	autoTLSRecent[key] = now
	return true
}

var calibrateMu sync.Mutex

// CalibrateAetherTLS measures this network now (the "Measure" button) and
// returns a summary. It dials WARP's gateways directly, so it refuses to run
// while the proxy or VPN is up, where it would measure the tunnel instead.
func CalibrateAetherTLS(privateDir string) (string, error) {
	if ProxyReady() {
		return "", errors.New("disconnect first: the measurement must see this network, not the tunnel")
	}
	if !calibrateMu.TryLock() {
		return "", errors.New("a measurement is already running")
	}
	defer calibrateMu.Unlock()
	o := currentAetherTLS()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := tlsshape.Calibrate(ctx, o, tlsCalibrationConfig(privateDir))
	if key := tlsNetworkKey(); key != "" {
		_ = tlsshape.Save(tlsCalibrationPath(privateDir), key, r)
	}
	return summarizeCalibration(r), nil
}

func summarizeCalibration(r tlsshape.Result) string {
	if len(r.Gateways) == 0 {
		return "No WARP HTTP/2 gateway accepted a TCP connection: the addresses themselves are blocked, which F&F cannot change."
	}
	if !r.Reached() {
		return "No MASQUE hello reached WARP's gateway; profiles keep their order."
	}
	pick := func(v string) string {
		if v == "" {
			return "none passed"
		}
		return v
	}
	passed := 0
	for _, t := range r.Trials {
		if t.OK > 0 {
			passed++
		}
	}
	return fmt.Sprintf("SNI %s · fingerprint %s · F&F twin %s · fragment %s · %d of %d shapes passed",
		pick(r.SNI), pick(r.Fingerprint), pick(r.AltFingerprint), pick(r.Fragment), passed, len(r.Trials))
}
