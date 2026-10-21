package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
)

var registerMu sync.Mutex

// RegisterAetherIdentity obtains missing WARP keys while KTest is
// disconnected: first through another app's local SOCKS5 proxy (via, may be
// empty), then over the current network, which another active VPN carries.
// This is the route Patterniha advises since cloudflare-ech.com was blocked
// (2026-10-21): get the key elsewhere once, then turn the other VPN off.
// Existing keys are never replaced; registration output is never logged.
func RegisterAetherIdentity(nativeLibraryDir, privateDir, via string) (string, error) {
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
	type result struct {
		Protocol string `json:"protocol"`
		Ready    bool   `json:"ready"`
		Error    string `json:"error,omitempty"`
	}
	var results []result
	for _, identity := range []struct{ name, protocol string }{{"masque.toml", "masque"}, {"wg.toml", "wg"}} {
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
