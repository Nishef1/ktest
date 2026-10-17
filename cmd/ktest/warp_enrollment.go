package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Nishef1/ktest/internal/front"
	"github.com/pelletier/go-toml/v2"
)

// Match Aether v2.3.0's persisted identity, without logging credentials or
// asking Aether to load it (Aether can rename damaged files or call the API).
func checkWarpIdentity(path, protocol string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return errors.New("identity cannot be read")
	}
	var id struct {
		Device  string `toml:"device_id"`
		Token   string `toml:"access_token"`
		IPv4    string `toml:"ipv4"`
		IPv6    string `toml:"ipv6"`
		Private string `toml:"wg_private_key"`
		Peer    string `toml:"wg_peer_public_key"`
		Cert    string `toml:"cert_pem"`
		Key     string `toml:"key_pem"`
	}
	if len(data) > 1<<20 || toml.Unmarshal(data, &id) != nil {
		return errors.New("invalid identity TOML; saved file kept")
	}
	if id.Device == "" || id.Token == "" || net.ParseIP(id.IPv4) == nil || (id.IPv6 != "" && net.ParseIP(id.IPv6) == nil) {
		return errors.New("identity is incomplete; saved file kept")
	}
	for _, key := range []string{id.Private, id.Peer} {
		b, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(b) != 32 {
			return errors.New("invalid WireGuard key; saved file kept")
		}
	}
	if protocol == "masque" {
		pair, err := tls.X509KeyPair([]byte(id.Cert), []byte(id.Key))
		if err != nil {
			return errors.New("invalid MASQUE certificate/key pair; saved file kept")
		}
		cert, err := x509.ParseCertificate(pair.Certificate[0])
		now := time.Now()
		if err != nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return errors.New("MASQUE certificate expired or not yet valid; check the clock or explicitly remove and register again")
		}
	}
	return nil
}

type enrollmentRoute struct {
	label string
	args  []string
}

// Registration is HTTPS for both protocols. A Psiphon carrier here carries
// only enrollment, not subsequent WireGuard traffic. An IP override alone
// still exposes the API's TLS name; ECH is supplied explicitly when available.
func enrollmentRoutes(ctx context.Context, base, proxy, ech, ip string) []enrollmentRoute {
	var routes []enrollmentRoute
	if proxy != "" {
		c, err := (&net.Dialer{Timeout: 300 * time.Millisecond}).DialContext(ctx, "tcp", proxy)
		if err == nil {
			c.Close()
			routes = append(routes, enrollmentRoute{"local proxy", []string{"--upstream", "socks5://" + proxy}})
		}
	}
	if ech == "" {
		fctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if cfg, addr, err := front.FetchCloudflareECH(fctx); err == nil {
			ech, ip = base64.StdEncoding.EncodeToString(cfg), addr
		}
		cancel()
	}
	if ech != "" && ip != "" {
		routes = append(routes, enrollmentRoute{"ECH", []string{"--ech", ech, "--enroll-address", ip}})
	}
	if fileOK(psiphonCore(base)) {
		bin, _ := filepath.Abs(psiphonCore(base))
		routes = append(routes, enrollmentRoute{"Psiphon CDN bootstrap", []string{
			"--psiphon-reverse", "--psiphon-mode", "cdn", "--psiphon-bin", bin,
			"--psiphon-bind", "127.0.0.1:0",
		}})
	}
	return append(routes, enrollmentRoute{"fragmented API HTTPS", []string{"--api-fragment"}})
}

type enrollmentRunner func(context.Context, string, []string) error

func runEnrollment(ctx context.Context, bin string, args []string) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	// Do not print the core's registration output: it can contain tokens/keys.
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	configureEnrollmentProcess(cmd)
	return cmd.Run()
}

func enrollWarpIdentity(ctx context.Context, u *term, bin, protocol string, routes []enrollmentRoute, run enrollmentRunner) error {
	path := identityFile()
	if protocol == "wg" {
		path = wireguardIdentityFile()
	}
	return enrollWarpIdentityAt(ctx, u, bin, protocol, path, routes, run)
}

func enrollWarpIdentityAt(ctx context.Context, u *term, bin, protocol, path string, routes []enrollmentRoute, run enrollmentRunner) error {
	if err := checkWarpIdentity(path, protocol); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err // never silently replace an existing identity
	}
	if err := os.MkdirAll(warpDir(), 0o700); err != nil {
		return err
	}
	for _, route := range routes {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Every route gets a clean staging file. A partial/failed registration
		// must not become a saved identity or be adopted by the next attempt.
		dir, err := os.MkdirTemp(warpDir(), ".enroll-")
		if err != nil {
			return err
		}
		step := u.Progress(fmt.Sprintf("Registering %s via %s", protocol, route.label), 1)
		stage := filepath.Join(dir, filepath.Base(path))
		masquePath, wgPath := filepath.Join(dir, "masque.toml"), filepath.Join(dir, "wg.toml")
		if protocol == "wg" {
			wgPath = stage
		} else {
			masquePath = stage
		}
		args := append([]string(nil), route.args...)
		args = append(args, "--register", protocol, "--config", filepath.Join(dir, "aether.toml"),
			"--masque-config", masquePath, "--wg-config", wgPath, "--log-level", "error")
		actx, cancel := context.WithTimeout(ctx, 60*time.Second)
		err = run(actx, bin, args)
		cancel()
		if err == nil {
			err = checkWarpIdentity(stage, protocol)
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err == nil {
			// Same filesystem, atomic no-replace publication. Another process
			// may have registered meanwhile; its identity must never be lost.
			err = os.Chmod(stage, 0o600)
			if err == nil {
				err = os.Link(stage, path)
			}
			if errors.Is(err, os.ErrExist) {
				err = checkWarpIdentity(path, protocol)
			}
			if err != nil {
				step.Finish(toneFail, "identity could not be saved")
				_ = os.RemoveAll(dir)
				return fmt.Errorf("cannot publish identity: %w", err)
			}
		}
		_ = os.RemoveAll(dir) // task-created staging directory only
		if err == nil {
			step.Finish(toneOK, "validated / saved")
			return nil
		}
		step.Finish(toneWarn, "not registered; existing keys kept")
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return errors.New("no registration route succeeded; API may be blocked (saved keys kept)")
}
