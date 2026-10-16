package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/dnscheck"
	"github.com/Nishef1/ktest/internal/front"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

// Which way out works is a property of the network, not of the program: one
// operator drops QUIC, another lets only QUIC v2 through, another resets any
// ClientHello that names cloudflareclient.com, another blocks the WARP gateways
// altogether. Aether can do all of it, so ktest does not pick; it keeps a list
// of ways to run Aether (WARP over MASQUE on HTTP/2 or HTTP/3, WireGuard with
// obfuscation, over IPv6, and Psiphon, which does not depend on WARP at all),
// tries them two at a time, keeps the first that opens a tunnel, and tries the
// one that worked last time first.

// defaultAetherProfiles is the shipped list; profiles/aether-profiles.txt
// replaces it. {ECH} and {ECHIP} are an ECH configuration and a Cloudflare edge
// address that ktest fetched itself, with no DNS: they make the calls to the
// WARP API (the key) possible where the API's name is filtered. A line that uses
// them is skipped when they could not be fetched.
const defaultAetherProfiles = `# Aether profiles, one per line:  label | flags
# They are tried two at a time in this order, the last one that worked first.
# ktest adds the loopback bind address, the identity files and the prompts' answers.
Psiphon | --psiphon-only
WARP, MASQUE over HTTP/2 with ECH | --masque --h2 --no-fragment --ech {ECH} --enroll-address {ECHIP}
WARP, MASQUE over HTTP/3 (QUIC) with ECH | --masque --h3 --ech {ECH} --enroll-address {ECHIP}
WARP, WireGuard | --wg --noize balanced --ech {ECH} --enroll-address {ECHIP}
WARP, MASQUE over HTTP/2, fragmented | --masque --h2 --api-fragment
WARP, WireGuard, aggressive obfuscation | --wg --noize aggressive --ech {ECH} --enroll-address {ECHIP}
WARP, MASQUE over HTTP/2 with ECH, IPv6 | --masque --h2 --no-fragment -6 --ech {ECH} --enroll-address {ECHIP}
Psiphon through CDN fronting | --psiphon-only --psiphon-mode cdn
WARP, MASQUE over HTTP/2 with ECH, thorough scan | --masque --h2 --no-fragment --scan thorough --startup-secs 100 --ech {ECH} --enroll-address {ECHIP}
`

// aetherProfile is one way of running Aether.
type aetherProfile struct {
	Label string
	Args  []string
}

func (p aetherProfile) has(flag string) bool {
	for _, a := range p.Args {
		if a == flag {
			return true
		}
	}
	return false
}

func (p aetherProfile) psiphon() bool { return p.has("--psiphon-only") }

// parseAetherProfiles reads "label | flags" lines, substituting the ECH
// placeholders and dropping lines that need what is not available.
func parseAetherProfiles(text, ech, ip string) ([]aetherProfile, error) {
	var out []aetherProfile
	seen := map[string]bool{}
	for n, line := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		label, flags, ok := strings.Cut(line, "|")
		label, flags = strings.TrimSpace(label), strings.TrimSpace(flags)
		if !ok || label == "" || flags == "" {
			return nil, fmt.Errorf("line %d: want \"label | flags\"", n+1)
		}
		if strings.Contains(flags, "--bind") || strings.Contains(flags, "--config") || strings.Contains(flags, "--masque-config") || strings.Contains(flags, "--wg-config") {
			return nil, fmt.Errorf("line %d: --bind and the identity paths are set by ktest", n+1)
		}
		if strings.Contains(flags, "{ECH") && (ech == "" || ip == "") {
			continue
		}
		flags = strings.NewReplacer("{ECHIP}", ip, "{ECH}", ech).Replace(flags)
		if seen[label] {
			return nil, fmt.Errorf("line %d: duplicate label %q", n+1, label)
		}
		seen[label] = true
		out = append(out, aetherProfile{Label: label, Args: strings.Fields(flags)})
	}
	return out, nil
}

func aetherProfilesFile(base string) string {
	return filepath.Join(base, "profiles", "aether-profiles.txt")
}

// loadAetherProfiles reads the editable list when it exists, else the default.
func loadAetherProfiles(base, ech, ip string) ([]aetherProfile, error) {
	text := defaultAetherProfiles
	if b, err := os.ReadFile(aetherProfilesFile(base)); err == nil {
		text = string(b)
	}
	return parseAetherProfiles(text, ech, ip)
}

// aetherRunArgs is the full command line of a profile on a local port. Every
// prompt Aether would ask has a flag here, so it never waits for input; flags
// the profile sets itself are not repeated.
func aetherRunArgs(i int, p aetherProfile, port int) []string {
	args := append([]string(nil), p.Args...)
	has := func(flags ...string) bool {
		for _, f := range flags {
			if p.has(f) {
				return true
			}
		}
		return false
	}
	if !p.psiphon() {
		if !has("-4", "-6", "--dual", "--ip") {
			args = append(args, "-4")
		}
		if !has("--scan", "--turbo", "--balanced", "--thorough", "--verified", "--ironclad") {
			args = append(args, "--turbo")
		}
		if !has("--startup-secs") {
			args = append(args, "--startup-secs", "45")
		}
		args = append(args, "--quick-reconnect")
	}
	return append(args,
		"--log-level", "warn",
		"--bind", fmt.Sprintf("127.0.0.1:%d", port),
		"--config", filepath.Join(warpDir(), fmt.Sprintf("run-%d.toml", i+1)),
		"--masque-config", identityFile(),
		"--wg-config", filepath.Join(warpDir(), "wg.toml"),
	)
}

// attemptTimeout is how long a profile may take to open its proxy port.
func attemptTimeout(p aetherProfile) time.Duration {
	secs := 45
	for i, a := range p.Args {
		if a == "--startup-secs" && i+1 < len(p.Args) {
			fmt.Sscanf(p.Args[i+1], "%d", &secs)
		}
	}
	return time.Duration(secs+20) * time.Second
}

func lastGoodFile() string { return filepath.Join(warpDir(), "last-profile.txt") }

// lastGoodFirst moves the profile that worked last time to the front.
func lastGoodFirst(ps []aetherProfile, last string) []aetherProfile {
	out := make([]aetherProfile, 0, len(ps))
	for _, p := range ps {
		if p.Label == last {
			out = append(out, p)
		}
	}
	for _, p := range ps {
		if p.Label != last {
			out = append(out, p)
		}
	}
	return out
}

// aetherPorts: one fixed port per profile index, so a profile that is found
// again after a drop is the same upstream.
func aetherPort(i int) int { return aetherBasePort + i }

type warpManager struct {
	o      connectOptions
	proxy  *smartproxy.Proxy
	dns    *dnscheck.Result
	t      *term
	profs  []aetherProfile
	logsMu sync.Mutex
	files  []*os.File
}

// startWarp runs the search for a working exit in the background and returns
// the note for the result box and the function that stops everything.
func startWarp(ctx context.Context, o connectOptions, proxy *smartproxy.Proxy, dns *dnscheck.Result, t *term) (string, func()) {
	if o.noWarp {
		return "off (-no-warp)", func() {}
	}
	if warpState(o.base) == "no core" {
		return "off - optional: `ktest warp -enable` adds exit paths (WARP, Psiphon) for Telegram and sites blocked by address", func() {}
	}
	ech, ip := "", ""
	fctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	if cfg, addr, err := front.FetchCloudflareECH(fctx); err == nil {
		ech, ip = base64.StdEncoding.EncodeToString(cfg), addr
	}
	cancel()
	profs, err := loadAetherProfiles(o.base, ech, ip)
	if err != nil || len(profs) == 0 {
		msg := "no usable profile"
		if err != nil {
			msg = err.Error()
		}
		return "off - " + msg + " (" + aetherProfilesFile(o.base) + ")", func() {}
	}
	if !fileOK(psiphonCore(o.base)) {
		var kept []aetherProfile
		for _, p := range profs {
			if !p.psiphon() {
				kept = append(kept, p)
			}
		}
		if len(kept) < len(profs) {
			t.Note("Psiphon profiles skipped: its helper is missing; `ktest warp -enable` fetches it")
		}
		profs = kept
	}
	_ = os.MkdirAll(warpDir(), 0o700)
	last, _ := os.ReadFile(lastGoodFile())
	m := &warpManager{o: o, proxy: proxy, dns: dns, t: t, profs: lastGoodFirst(profs, strings.TrimSpace(string(last)))}
	mctx, stopManager := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.run(mctx)
	}()
	return fmt.Sprintf("searching: %d ways to try, two at a time (up to a few minutes)", len(profs)), func() {
		stopManager()
		<-done
		m.logsMu.Lock()
		for _, f := range m.files {
			_ = f.Close()
		}
		m.logsMu.Unlock()
	}
}

// maxExits is how many tunnels are kept open at once.
const maxExits = 3

// run searches, holds the tunnels that were found until all of them have ended,
// and searches again; after a round with no result it waits before the next.
func (m *warpManager) run(ctx context.Context) {
	for ctx.Err() == nil {
		found := m.search(ctx)
		if len(found) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Minute):
			}
			continue
		}
		for _, w := range found {
			select {
			case <-ctx.Done():
				for _, x := range found {
					x.rc.cancel()
					x.rc.stop()
				}
				return
			case <-w.rc.done:
				m.t.Line(toneWarn, "%s ended", w.p.Label)
				w.rc.stop()
			}
		}
		m.t.Line(toneWarn, "Every exit path ended; searching again")
	}
}

type warpFound struct {
	p    aetherProfile
	port int
	rc   *runningCore
}

// search runs the profiles two at a time. Every tunnel that opens its port is
// added to the race at once and kept; the search ends when the list is used up
// or maxExits tunnels are open.
func (m *warpManager) search(ctx context.Context) []*warpFound {
	var (
		mu    sync.Mutex
		next  int
		found []*warpFound
		wg    sync.WaitGroup
	)
	take := func() (int, bool) {
		mu.Lock()
		defer mu.Unlock()
		if len(found) >= maxExits || next >= len(m.profs) {
			return 0, false
		}
		next++
		return next - 1, true
	}
	began := time.Now()
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				i, ok := take()
				if !ok {
					return
				}
				p := m.profs[i]
				up, rc := m.try(ctx, i, p)
				if !up {
					continue
				}
				rank := 5 // WARP: faster and steadier
				if p.psiphon() {
					rank = 6
				}
				err := m.proxy.Add(smartproxy.Upstream{
					Name: "Exit: " + p.Label, Addr: fmt.Sprintf("127.0.0.1:%d", aetherPort(i)), Rank: rank, Exit: true, Late: true,
				})
				mu.Lock()
				found = append(found, &warpFound{p: p, port: aetherPort(i), rc: rc})
				first := len(found) == 1
				mu.Unlock()
				if err == nil {
					if first {
						_ = os.WriteFile(lastGoodFile(), []byte(p.Label), 0o600)
					}
					m.t.Line(toneOK, "Exit ready: %s %s", p.Label, m.t.Dim("("+shortDur(time.Since(began))+"). Telegram and sites blocked by address can open now"))
				}
			}
		}()
	}
	wg.Wait()
	if len(found) == 0 && ctx.Err() == nil {
		m.t.Line(toneWarn, "No exit path came up (%d tried); trying again in two minutes. Logs are in %s", len(m.profs), warpDir())
	}
	return found
}

// try starts one profile and waits for its proxy port. On success the process
// keeps running; on failure it is stopped.
func (m *warpManager) try(ctx context.Context, i int, p aetherProfile) (bool, *runningCore) {
	port := aetherPort(i)
	if err := portFree(port); err != nil {
		m.t.Note("skipped %s: %v", p.Label, err)
		return false, nil
	}
	logs := &tailBuffer{max: 8192}
	logPath := filepath.Join(warpDir(), fmt.Sprintf("aether-%d.log", i+1))
	var sinks []io.Writer
	if lf, err := os.Create(logPath); err == nil {
		m.logsMu.Lock()
		m.files = append(m.files, lf)
		m.logsMu.Unlock()
		sinks = append(sinks, lf)
	}
	if m.o.verbose {
		sinks = append(sinks, os.Stderr)
	}
	if len(sinks) > 0 {
		logs.tee = io.MultiWriter(sinks...)
	}
	cctx, cancel := context.WithCancel(ctx)
	rc := &runningCore{cancel: cancel, done: make(chan struct{})}
	l := aetherLauncher(aetherBinary(m.o.base), aetherRunArgs(i, p, port), logs)
	go func() {
		rc.err = l(cctx, m.dns)
		close(rc.done)
	}()
	deadline := time.Now().Add(attemptTimeout(p))
	if waitForPort(ctx, rc.done, port, time.Until(deadline)) && exitCarries(ctx, rc.done, port, time.Until(deadline)) {
		return true, rc
	}
	rc.cancel()
	rc.stop()
	if ctx.Err() == nil {
		why := logs.lastLine()
		if rc.err != nil && why == "" {
			why = rc.err.Error()
		}
		m.t.Note("%s: no tunnel (%s)", p.Label, wrapOne(why, 110))
	}
	return false, nil
}

// exitCarries waits until a request really goes through the proxy on port. The
// port opens before some cores (Psiphon) have a tunnel, so an open port proves
// nothing: a TLS handshake with a Cloudflare name must complete through it.
func exitCarries(ctx context.Context, done <-chan struct{}, port int, limit time.Duration) bool {
	end := time.Now().Add(limit)
	for time.Now().Before(end) {
		select {
		case <-ctx.Done():
			return false
		case <-done:
			return false
		default:
		}
		hctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		c, err := smartproxy.DialVia(hctx, fmt.Sprintf("127.0.0.1:%d", port), "www.cloudflare.com", "443", 8*time.Second)
		if err == nil {
			tc := tls.Client(c, &tls.Config{ServerName: "www.cloudflare.com"})
			_ = c.SetDeadline(time.Now().Add(8 * time.Second))
			err = tc.HandshakeContext(hctx)
			_ = tc.Close()
		}
		cancel()
		if err == nil {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(2 * time.Second):
		}
	}
	return false
}
