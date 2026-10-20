package mobilebridge

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
	"github.com/Nishef1/ktest/internal/front"
)

// bootstrapAndroidWARP gives a phone with no VPN an initial path to Cloudflare
// registration: ECH with a key ktest fetched itself, then a local Fast
// anti-DPI SOCKS carrier when available, fragmented HTTPS and a Psiphon CDN
// reverse bootstrap using the same
// signed Android executable bundle. The last-resort native Aether startup can
// still attempt its own registration; a failed bootstrap never deletes keys.
// Registration output is discarded (it can contain access tokens).
func bootstrapAndroidWARP(ctx context.Context, o nativeOptions, paths aether.AndroidPaths, p aether.Profile) error {
	if p.Psiphon() || p.Has("--tor-only") {
		return nil
	}
	req := aether.IdentityRequirements(p)
	if len(req) == 0 {
		return nil
	}
	// Nested profiles use an outer WARP identity first; their inner key
	// material is staged by Aether when the outer tunnel is established.
	identity := req[0]
	path := filepath.Join(o.stateDir, identity.Name)
	if identity.Protocol == "masque" && aether.CheckIdentity(path, "masque") == nil {
		// A key can be intact on disk and refused by every gateway; then it
		// never connects. Set it aside (never deleted) and register anew.
		if verdict, err := aether.ProbeMasqueIdentity(ctx, paths.Aether, path); err == nil && verdict == aether.IdentityRejected {
			if _, err := aether.SetAsideRejectedIdentity(path); err != nil {
				return err
			}
		}
	}
	if err := aether.CheckIdentity(path, identity.Protocol); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	routes := []aether.EnrollmentRoute{}
	// ECH first, never with --fragment: where the API name itself is
	// filtered it is the route that registers (desktop, 2026-10-20).
	echCtx, stopECH := context.WithTimeout(ctx, 15*time.Second)
	if config, edge, err := front.FetchCloudflareECH(echCtx); err == nil {
		routes = append(routes, aether.EnrollmentRoute{
			Label: "ECH registration", Args: []string{"--ech", base64.StdEncoding.EncodeToString(config), "--api-address", edge},
		})
	}
	stopECH()
	if o.carrier != "" {
		routes = append(routes, aether.EnrollmentRoute{
			Label: "local Fast anti-DPI", Args: []string{"--upstream", "socks5://" + o.carrier},
		})
	}
	routes = append(routes, aether.EnrollmentRoute{
		Label: "fragmented registration TLS", Args: []string{"--fragment"},
	})
	if paths.Psiphon != "" {
		routes = append(routes, aether.EnrollmentRoute{
			Label: "Psiphon CDN registration", Args: []string{
				"--psiphon-reverse", "--psiphon-mode", "cdn",
				"--psiphon-bin", paths.Psiphon, "--psiphon-dir", filepath.Join(o.stateDir, "psiphon-enrollment"), "--psiphon-bind", "127.0.0.1:0",
			},
		})
	}
	probeCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	err := aether.EnrollIdentity(probeCtx, aether.EnrollmentOptions{
		Binary:   paths.Aether,
		Protocol: identity.Protocol,
		Path:     path,
		StateDir: o.stateDir,
		Routes:   routes,
		Run:      aether.RunEnrollment,
	})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Do not preempt Aether's own provisioning or discard a
		// still-usable key when a particular reverse route is blocked.
		if errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return nil
}
