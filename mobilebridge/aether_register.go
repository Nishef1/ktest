package mobilebridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
	"github.com/Nishef1/ktest/internal/front"
)

var registerMu sync.Mutex

// RegisterAetherIdentity obtains missing WARP keys while KTest is
// disconnected: use a user-supplied local proxy (if set), then native direct
// WARP API routes including Cloudflare edge fallback, then fragmented HTTPS.
// An existing VPN is only an optional carrier for the direct route.
// Existing keys are never replaced; registration output is never logged.
func RegisterAetherIdentity(nativeLibraryDir, privateDir, via string) (string, error) {
	return RegisterAetherIdentityKind(nativeLibraryDir, privateDir, via, "both")
}

// RegisterAetherIdentityKind registers only the requested WARP credential.
// Android 10 clients can have a valid MASQUE identity even if WG fails.
// Never replace or delete an existing identity.
func RegisterAetherIdentityKind(nativeLibraryDir, privateDir, via, kind string) (string, error) {
	if kind != "masque" && kind != "wg" && kind != "both" {
		return "", errors.New("choose MASQUE, WireGuard or both WARP key kinds")
	}
	if !filepath.IsAbs(privateDir) {
		return "", errors.New("WARP registration requires an app-private absolute path")
	}
	if ProxyReady() {
		return "", errors.New("disconnect KTest first; a running connection must not switch identities")
	}
	if !registerMu.TryLock() {
		return "", errors.New("WARP registration is already running")
	}
	defer registerMu.Unlock()
	paths, err := aether.AndroidBundlePaths(nativeLibraryDir, runtime.GOARCH)
	if err != nil {
		return "", err
	}
	stateDir := filepath.Join(privateDir, "aether")
	if _, err := aether.MigrateIdentityFiles(stateDir, filepath.Join(privateDir, "automatic-exits")); err != nil {
		return "", err
	}
	ctx := context.Background()
	var routes []aether.EnrollmentRoute
	if via != "" {
		route, err := aether.ViaProxyRoute(ctx, via)
		if err != nil {
			return "", err
		}
		routes = append(routes, route)
	}
	routes = append(routes, aether.DirectRoute,
		aether.EnrollmentRoute{Label: "fragmented registration TLS", Args: []string{"--fragment"}, Timeout: 30 * time.Second})
	// Match automatic WARP registration without requiring ECH or Psiphon.
	// Both are late fallbacks on networks blocking every direct API route.
	echCtx, stopECH := context.WithTimeout(ctx, 3*time.Second)
	if cfg, edge, err := front.SharedCloudflareECH(echCtx); err == nil {
		routes = append(routes, aether.EnrollmentRoute{
			Label: "ECH registration", Args: []string{
				"--fragment", "--ech", base64.StdEncoding.EncodeToString(cfg),
				"--api-address", edge,
			}, Timeout: 25 * time.Second,
		})
	}
	stopECH()
	if paths.Psiphon != "" {
		routes = append(routes, aether.EnrollmentRoute{
			Label: "Psiphon CDN registration",
			Args: []string{"--psiphon-reverse", "--psiphon-mode", "cdn",
				"--psiphon-bin", paths.Psiphon, "--psiphon-dir",
				filepath.Join(stateDir, "psiphon-enrollment"),
				"--psiphon-bind", "127.0.0.1:0"},
			Timeout: 150 * time.Second,
		})
	}
	type result struct {
		Protocol string `json:"protocol"`
		Ready    bool   `json:"ready"`
		Error    string `json:"error,omitempty"`
	}
	var results []result
	for _, identity := range []struct{ name, protocol string }{{"masque.toml", "masque"}, {"wg.toml", "wg"}} {
		if kind != "both" && kind != identity.protocol {
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, aether.EnrollmentBudget(routes))
		err := aether.EnrollIdentity(rctx, aether.EnrollmentOptions{
			Binary: paths.Aether, Protocol: identity.protocol,
			Path: filepath.Join(stateDir, identity.name), StateDir: stateDir,
			Routes: routes, Run: aether.RunEnrollment,
		})
		cancel()
		r := result{Protocol: identity.protocol, Ready: err == nil}
		if err != nil {
			r.Error = err.Error()
		}
		results = append(results, r)
	}
	raw, _ := json.Marshal(struct {
		Results []result `json:"results"`
	}{results})
	return string(raw), nil
}
