package mobilebridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
	"github.com/Nishef1/ktest/internal/egresscheck"
)

type nativeOptions struct {
	method, libraryDir, stateDir string
	// viaFast carries Aether through a private Fast proxy (carrier address).
	viaFast    bool
	privateDir string
	carrier    string
	profile    *aether.Profile // automatic discovery preserves exact variants
}

type nativeCore struct {
	address string
	method  string
	cancel  context.CancelFunc
	done    chan struct{}
	err     error // read only after done closes
}

// StartNativeProxy runs the packaged Aether core, including its existing Tor
// and Psiphon backends. The core owns enrollment, gateway scans and reconnect;
// KTest owns process lifetime and the existing fail-closed route policy.
// Both paths come from Android ApplicationInfo/filesDir, never a download.
func StartNativeProxy(mode, method, libraryDir, stateDir string) (string, error) {
	if mode != "aether" && mode != "tor" && mode != "psiphon" {
		return "", errors.New("managed native startup requires Aether, Tor or Psiphon mode")
	}
	return startProxy(mode, "", &nativeOptions{method: method, libraryDir: libraryDir, stateDir: stateDir}, "")
}

func nativeProfile(mode, method string, viaFast bool) (aether.Profile, error) {
	if !aether.ValidMethod(method) {
		return aether.Profile{}, errors.New("unknown Aether method")
	}
	if mode == "tor" {
		if method != "" && method != "auto" {
			return aether.Profile{}, errors.New("Tor uses its dedicated Aether backend")
		}
		return aether.Profile{Label: "Tor-only", Args: []string{"--tor-only"}}, nil
	}
	profiles, err := aether.ParseProfiles(aether.DefaultProfiles, "", "")
	if err != nil {
		return aether.Profile{}, err
	}
	profiles = aether.FilterMethod(aether.ProfilesForMode(profiles, mode), method)
	if viaFast {
		profiles = tcpCarriedProfiles(profiles)
		if len(profiles) == 0 {
			return aether.Profile{}, errors.New("through Fast only TCP methods work (MASQUE, Gool or MASQUE-in-MASQUE over HTTP/2); choose one of those")
		}
	}
	if len(profiles) == 0 {
		return aether.Profile{}, errors.New("selected method is incompatible with this mode")
	}
	// Default means the first shipped compatible profile, not an invented
	// cross-protocol scanner. Users can select another existing native method.
	return profiles[0], nil
}

func launchNative(ctx context.Context, mode string, o nativeOptions) (*nativeCore, error) {
	p, err := nativeProfile(mode, o.method, o.carrier != "")
	if o.profile != nil {
		p, err = *o.profile, nil
	}
	if err != nil {
		return nil, err
	}
	paths, err := aether.AndroidBundlePaths(o.libraryDir, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(o.stateDir) || filepath.Clean(o.stateDir) == filepath.Clean(o.libraryDir) {
		return nil, errors.New("native state requires a separate absolute private directory")
	}
	if err := os.MkdirAll(o.stateDir, 0700); err != nil {
		return nil, fmt.Errorf("native private state: %w", err)
	}
	supported, err := aether.InspectProfiles(ctx, paths.Aether, []aether.Profile{p})
	if err != nil {
		return nil, err
	}
	if len(supported) == 0 {
		return nil, errors.New("packaged Aether does not support this profile")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	address := listener.Addr().String()
	_ = listener.Close() // Aether binds its own socket; no inherited-fd API.
	args := paths.ProfileArgs(p, port, o.stateDir)
	if p.LocalCarrier() {
		args, err = aether.BindLocalCarrier(args, o.carrier)
		if err != nil {
			return nil, err
		}
	} else if o.carrier != "" {
		args = append(args, "--upstream", "socks5://"+o.carrier)
	}
	runCtx, cancel := context.WithCancel(context.Background())
	n := &nativeCore{address: address, method: p.Method(), cancel: cancel, done: make(chan struct{})}
	go func() {
		// Raw native output can contain identifiers or credentials. Do not
		// forward it to the UI, Android logcat or shared storage.
		n.err = aether.Run(runCtx, paths.Aether, args, io.Discard)
		close(n.done)
	}()
	return n, nil
}

func (n *nativeCore) stop() {
	n.cancel()
	<-n.done // shared runner bounds Wait and terminates owned descendants
}

func verifyModeUpstream(ctx context.Context, mode, address string) (observedExit, error) {
	checked, err := verifyLocalUpstream(ctx, address)
	if err == nil && mode == "tor" {
		err = egresscheck.ProbeTorExit(ctx, checked.Address)
	}
	return checked, err
}

func waitNative(ctx context.Context, mode string, n *nativeCore) (observedExit, error) {
	return waitNativeWithProbe(ctx, mode, n, verifyModeUpstream)
}

// The probe can complete just as an owned Aether process exits. Never accept
// the observed foreign IP alone as evidence of an *active* local transport.
func waitNativeWithProbe(ctx context.Context, mode string, n *nativeCore, probe func(context.Context, string, string) (observedExit, error)) (observedExit, error) {
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return observedExit{}, fmt.Errorf("native startup canceled or timed out; the selected method or verification endpoint may be unreachable (last check: %v): %w", lastErr, err)
		}
		select {
		case <-n.done:
			if n.err != nil {
				return observedExit{}, fmt.Errorf("Aether core exited before verification: %w", n.err)
			}
			return observedExit{}, errors.New("Aether core exited before verification")
		default:
		}
		checked, err := probe(ctx, mode, n.address)
		if err == nil {
			// A completed HTTPS exit check can race cancellation and a native
			// process exit. Both conditions must still be false at promotion.
			if ctx.Err() != nil {
				return observedExit{}, ctx.Err()
			}
			select {
			case <-n.done:
				if n.err != nil {
					return observedExit{}, fmt.Errorf("Aether core exited during verification: %w", n.err)
				}
				return observedExit{}, errors.New("Aether core exited during verification")
			default:
				return checked, nil
			}
		}
		lastErr = err
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
		case <-n.done:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// Fast relays TCP (and DNS) only, so UDP-based Aether transports (HTTP/3,
// WireGuard) and separate Psiphon/Tor helpers cannot use it as an upstream.
func tcpCarriedProfiles(profiles []aether.Profile) []aether.Profile {
	var out []aether.Profile
	for _, p := range profiles {
		if aether.CanCarryLocally(p) {
			out = append(out, p)
		}
	}
	return out
}
