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

// identityCheckBudget leaves room for the two-gateway rejection quorum; a
// filtered path ends after two gateways without TLS (8s each).
const identityCheckBudget = 30 * time.Second

// bootstrapAndroidWARP gives a phone with no VPN several bounded paths to
// Cloudflare registration. A working local Fast carrier and fragmented HTTPS
// are tried before ECH because the visible cloudflare-ech.com SNI has been
// reported filtered on some networks. Psiphon CDN remains an independent
// fallback. Failure never deletes saved keys; registration output is discarded.
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
		// Two credential refusals are needed; a refusal arrives seconds after
		// TLS, and a gateway without TLS is abandoned after 8s.
		checkCtx, stopCheck := context.WithTimeout(ctx, identityCheckBudget)
		verdict, checkErr := aether.ProbeMasqueIdentity(checkCtx, paths.Aether, path)
		stopCheck()
		if checkErr == nil && verdict == aether.IdentityRejected {
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
	if o.carrier != "" {
		routes = append(routes, aether.EnrollmentRoute{
			Label: "local Fast anti-DPI", Args: []string{"--upstream", "socks5://" + o.carrier},
			Timeout: 30 * time.Second,
		})
	}
	routes = append(routes, aether.EnrollmentRoute{
		Label: "fragmented registration TLS", Args: []string{"--fragment"},
		Timeout: 30 * time.Second,
	})
	echCtx, stopECH := context.WithTimeout(ctx, 3*time.Second)
	if config, edge, err := front.SharedCloudflareECH(echCtx); err == nil {
		routes = append(routes, aether.EnrollmentRoute{
			Label: "ECH registration", Args: []string{"--ech", base64.StdEncoding.EncodeToString(config), "--api-address", edge},
			Timeout: 25 * time.Second,
		})
	}
	stopECH()
	if paths.Psiphon != "" {
		routes = append(routes, aether.EnrollmentRoute{
			Label: "Psiphon CDN registration", Args: []string{
				"--psiphon-reverse", "--psiphon-mode", "cdn",
				"--psiphon-bin", paths.Psiphon, "--psiphon-dir", filepath.Join(o.stateDir, "psiphon-enrollment"), "--psiphon-bind", "127.0.0.1:0",
			},
		})
	}
	// Each route has its own bound; the whole transaction gets their sum so
	// the last fallback (Psiphon) is always reached.
	probeCtx, cancel := context.WithTimeout(ctx, aether.EnrollmentBudget(routes))
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
