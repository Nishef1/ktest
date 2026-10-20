package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/Nishef1/ktest/internal/aether"
	"github.com/Nishef1/ktest/internal/front"
)

func checkWarpIdentity(path, protocol string) error { return aether.CheckIdentity(path, protocol) }

type enrollmentRoute struct {
	label string
	args  []string
}

// Fast's no-Psiphon/Tor rule also applies before WARP identity enrollment.
func fastEnrollmentRoutes(routes []enrollmentRoute) []enrollmentRoute {
	var local []enrollmentRoute
	for _, route := range routes {
		p := aether.Profile{Args: route.args}
		if p.Psiphon() || p.Has("--psiphon") || p.Has("--psiphon-reverse") || p.Has("--tor-only") || p.Has("--tor") || p.Has("--tor-reverse") {
			continue
		}
		local = append(local, route)
	}
	return local
}

// Registration is HTTPS for both protocols. A Psiphon carrier here carries
// only enrollment, not subsequent WireGuard traffic. An IP override alone
// still exposes the API's TLS name; ECH is supplied explicitly when available.
// ECH goes first and never with --fragment: measured on an Iranian ISP
// (2026-10-20), the API name was cut whatever the splitting (TCP segments,
// TLS records, ByeDPI, Aether's own fragmenting), while ECH with an
// unfiltered outer name (cloudflare-ech.com) registered at once. Each failed
// route costs about a minute of retries before the next one runs.
func enrollmentRoutes(ctx context.Context, base, proxy, ech, ip string) []enrollmentRoute {
	var routes []enrollmentRoute
	if ech == "" {
		fctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if cfg, addr, err := front.FetchCloudflareECH(fctx); err == nil {
			ech, ip = base64.StdEncoding.EncodeToString(cfg), addr
		}
		cancel()
	}
	if ech != "" && ip != "" {
		routes = append(routes, enrollmentRoute{"ECH", []string{"--ech", ech, "--api-address", ip}})
	}
	if proxy != "" {
		c, err := (&net.Dialer{Timeout: 300 * time.Millisecond}).DialContext(ctx, "tcp", proxy)
		if err == nil {
			c.Close()
			routes = append(routes, enrollmentRoute{"local proxy", []string{"--upstream", "socks5://" + proxy}})
		}
	}
	if fileOK(psiphonCore(base)) {
		bin, _ := filepath.Abs(psiphonCore(base))
		routes = append(routes, enrollmentRoute{"Psiphon CDN bootstrap", []string{
			"--psiphon-reverse", "--psiphon-mode", "cdn", "--psiphon-bin", bin,
			"--psiphon-bind", "127.0.0.1:0",
		}})
	}
	return append(routes, enrollmentRoute{"fragmented API HTTPS", []string{"--fragment"}})
}

type enrollmentRunner func(context.Context, string, []string) error

func runEnrollment(ctx context.Context, bin string, args []string) error {
	return aether.RunEnrollment(ctx, bin, args)
}

func enrollWarpIdentity(ctx context.Context, u *term, bin, protocol string, routes []enrollmentRoute, run enrollmentRunner) error {
	path := identityFile()
	if protocol == "wg" {
		path = wireguardIdentityFile()
	}
	return enrollWarpIdentityAt(ctx, u, bin, protocol, path, routes, run)
}

func enrollWarpIdentityAt(ctx context.Context, u *term, bin, protocol, path string, routes []enrollmentRoute, run enrollmentRunner) error {
	shared := make([]aether.EnrollmentRoute, len(routes))
	for i, route := range routes {
		shared[i] = aether.EnrollmentRoute{Label: route.label, Args: route.args}
	}
	var finish func(string)
	return aether.EnrollIdentity(ctx, aether.EnrollmentOptions{
		Binary: bin, Protocol: protocol, Path: path, StateDir: warpDir(), Routes: shared, Run: run,
		OnProgress: func(e aether.EnrollmentEvent) {
			if e.Phase == "registering" {
				step := u.Progress(fmt.Sprintf("Registering %s via %s", protocol, e.Route), 1)
				finish = func(phase string) {
					switch phase {
					case "saved":
						step.Finish(toneOK, "validated / saved")
					case "save_failed":
						step.Finish(toneFail, "identity could not be saved")
					default:
						step.Finish(toneWarn, "not registered; existing keys kept")
					}
				}
			} else if finish != nil {
				finish(e.Phase)
			}
		},
	})
}
