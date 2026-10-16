package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/dnscheck"
	"github.com/Nishef1/ktest/internal/front"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

// The WARP exit is the one path that does not depend on what a site's CDN
// accepts: Aether (an open-source Rust core, AGPL-3.0, run as a separate
// process like Xray and ByeDPI) tunnels MASQUE over HTTP/2 to Cloudflare WARP
// and serves SOCKS5. Traffic that uses it leaves from a Cloudflare address, so
// destinations that are blocked by address (Telegram) and sites that no front
// reaches open too. It is opt-in because it registers a free, anonymous WARP
// identity on this PC and sends the traffic that uses it through Cloudflare.
const (
	aetherVersion  = "v2.3.0"
	aetherZipURL   = "https://github.com/CluvexStudio/Aether/releases/download/v2.3.0/aether-windows-x86_64.zip"
	aetherZipSHA   = "0cc32dd2d7573f91d2e55d4f427bfe4c6f6252342494e1b410d61b12d1e4dc79"
	aetherBasePort = 10830
)

// warpDir keeps the WARP identity per user, never in the portable folder.
func warpDir() string {
	if d := os.Getenv("KTEST_WARP_DIR"); d != "" {
		return d
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "ktest", "warp")
}

func aetherBinary(base string) string {
	name := "aether"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(base, "cores", name)
}

func identityFile() string { return filepath.Join(warpDir(), "masque.toml") }

// warpState reports what is missing: "ready", "no core" or "no identity".
func warpState(base string) string {
	switch {
	case !fileOK(aetherBinary(base)):
		return "no core"
	case !fileOK(identityFile()):
		return "no identity"
	}
	return "ready"
}

// aetherProfile is one way of running the tunnel. Which one gets through
// depends on the firewall: the channel reports that Iran's firewall resets a
// ClientHello whose SNI is cloudflareclient.com unless it is fragmented, and
// that fragmentation is closed on the MCI-type firewall, where ECH works.
type aetherProfile struct {
	Label string
	Args  []string
}

// aetherProfiles lists the profiles. ech is the ECH configuration to hand to
// Aether (base64) and ip an edge address that was reached, so that neither a DNS
// lookup nor the WARP API's own name is needed; without them Aether is left to
// look the key up by DNS, which is what a filtering network denies it.
func aetherProfiles(ech, ip string) []aetherProfile {
	echo := []string{"--masque", "--h2", "--no-fragment", "--ech", "auto"}
	if ech != "" && ip != "" {
		echo = []string{"--masque", "--h2", "--no-fragment", "--ech", ech, "--enroll-address", ip}
	}
	return []aetherProfile{
		{"WARP exit, MASQUE over HTTP/2 with ECH", echo},
		{"WARP exit, MASQUE over HTTP/2, fragmented", []string{"--masque", "--h2", "--api-fragment"}},
	}
}

// aetherRunArgs is the full command line of profile i on a local port. Every
// prompt Aether would ask has a flag here, so it never waits for input.
func aetherRunArgs(i int, p aetherProfile, port int) []string {
	args := append([]string(nil), p.Args...)
	return append(args,
		"-4", "--turbo", "--quick-reconnect", "--startup-secs", "60", "--log-level", "warn",
		"--bind", fmt.Sprintf("127.0.0.1:%d", port),
		"--config", filepath.Join(warpDir(), fmt.Sprintf("run-%d.toml", i+1)),
		"--masque-config", identityFile(),
	)
}

// aetherLauncher runs Aether until ctx ends.
func aetherLauncher(bin string, args []string, output io.Writer) launcher {
	return func(ctx context.Context, _ *dnscheck.Result) error {
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Stdout, cmd.Stderr = output, output
		err := cmd.Run()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return fmt.Errorf("Aether exited: %w", err)
		}
		return errors.New("Aether exited unexpectedly")
	}
}

// fetchAether downloads the pinned Aether release, verifies its SHA-256 and
// extracts aether.exe into base/cores. Nothing else in the archive is used.
func fetchAether(ctx context.Context, url, sha, base string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 200<<20))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, sha) {
		return fmt.Errorf("checksum mismatch: got %s, pinned %s; the file was not used", got, sha)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	want := filepath.Base(aetherBinary(base))
	for _, f := range zr.File {
		if f.Name != want {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		if err := os.MkdirAll(filepath.Join(base, "cores"), 0o755); err != nil {
			return err
		}
		tmp := aetherBinary(base) + ".part"
		out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
		return os.Rename(tmp, aetherBinary(base))
	}
	return fmt.Errorf("the archive does not contain %s", want)
}

// registerAttempts are tried in turn. The route to the WARP API (the key) is
// closed on some networks, so the first ways in are the ones this program has
// already shown to work there: through ktest's own proxy when it runs, and
// with Encrypted Client Hello using a configuration ktest fetched itself and an
// address it reached, so that neither DNS nor the API's name is needed. The
// plain and fragmented routes come last.
func registerAttempts(proxyUp bool, ech, ip string) [][]string {
	var out [][]string
	if proxyUp {
		out = append(out, []string{"--upstream", "socks5://127.0.0.1:10800"})
	}
	if ech != "" && ip != "" {
		out = append(out, []string{"--ech", ech, "--enroll-address", ip})
	}
	return append(out, nil, []string{"--api-fragment"})
}

func registerWarp(ctx context.Context, u *term, bin string) error {
	if err := os.MkdirAll(warpDir(), 0o700); err != nil {
		return err
	}
	conn, derr := net.DialTimeout("tcp", connectListenDefault, 300*time.Millisecond)
	if derr == nil {
		conn.Close()
	}
	var lastLine string
	ech, ip := "", ""
	if cfg, addr, err := front.FetchCloudflareECH(ctx); err == nil {
		ech, ip = base64.StdEncoding.EncodeToString(cfg), addr
	}
	for i, extra := range registerAttempts(derr == nil, ech, ip) {
		step := u.Progress(fmt.Sprintf("Registering a WARP identity (try %d)", i+1), 1)
		actx, cancel := context.WithTimeout(ctx, 60*time.Second)
		logs := &tailBuffer{max: 4096}
		args := append(append([]string(nil), extra...), "--register", "masque",
			"--config", filepath.Join(warpDir(), "aether.toml"), "--masque-config", identityFile(), "--log-level", "warn")
		cmd := exec.CommandContext(actx, bin, args...)
		cmd.Stdout, cmd.Stderr = logs, logs
		err := cmd.Run()
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil && fileOK(identityFile()) {
			step.Finish(toneOK, "identity saved")
			return nil
		}
		lastLine = logs.lastLine()
		step.Finish(toneWarn, trimDetail(lastLine))
	}
	return fmt.Errorf("no registration route worked (last: %s)", lastLine)
}

// warpEnable makes the WARP exit available: the core, then the identity.
func warpEnable(ctx context.Context, u *term, base string) int {
	if !fileOK(aetherBinary(base)) {
		step := u.Progress("Downloading Aether "+aetherVersion, 1)
		if err := fetchAether(ctx, aetherZipURL, aetherZipSHA, base); err != nil {
			step.Finish(toneFail, err.Error())
			u.Note("Download %s yourself, check its SHA-256 (%s) and put aether.exe into %s.", aetherZipURL, aetherZipSHA, filepath.Join(base, "cores"))
			return 1
		}
		step.Finish(toneOK, "verified against the pinned SHA-256")
	}
	if !fileOK(identityFile()) {
		if err := registerWarp(ctx, u, aetherBinary(base)); err != nil {
			u.Line(toneFail, "%v", err)
			u.Note("Start Connect in another window first (the registration then goes through ktest), or register with another VPN on once; the identity is only needed once.")
			return 1
		}
	}
	u.Line(toneOK, "The WARP exit is enabled. Connect starts it in the background; Telegram and sites blocked by address open through it.")
	return 0
}

func warpDisable(u *term) int {
	dir := warpDir()
	if dir == "" {
		return 0
	}
	if err := os.RemoveAll(dir); err != nil {
		u.Line(toneFail, "cannot delete %s: %v", dir, err)
		return 1
	}
	u.Line(toneOK, "The WARP identity was deleted. The Aether core stays in cores/.")
	return 0
}

func warpStatus(u *term, base string) {
	u.Heading("WARP exit", "Leaves from a Cloudflare address, so destinations blocked by address (Telegram) open too.")
	switch s := warpState(base); s {
	case "ready":
		u.Line(toneOK, "Enabled: Connect starts it in the background and adds it to the race.")
		u.Note("identity %s", identityFile())
	case "no identity":
		u.Line(toneWarn, "The core is present but no WARP identity is registered: `ktest warp -enable`.")
	default:
		u.Line(toneInfo, "Off. `ktest warp -enable` downloads Aether %s (about 24 MB, pinned SHA-256) and registers a free anonymous WARP identity on this PC.", aetherVersion)
	}
	u.Note("Traffic that uses it goes through Cloudflare. It is the last resort: it joins a connection only after the other paths failed or took more than 3 seconds.")
}

const warpUsage = `usage: ktest warp [-enable | -disable] [-base DIR]

  (no flag)   show the state of the WARP exit
  -enable     download the Aether core if needed and register a WARP identity
  -disable    delete the WARP identity
`

// runWarp is `ktest warp`.
func runWarp(args []string) int {
	fs := flag.NewFlagSet("warp", flag.ContinueOnError)
	base := fs.String("base", defaultBase(), "")
	enable := fs.Bool("enable", false, "")
	disable := fs.Bool("disable", false, "")
	fs.Usage = func() { fmt.Fprint(os.Stderr, warpUsage) }
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	u := newTerm(os.Stdout)
	switch {
	case *enable:
		return warpEnable(context.Background(), u, *base)
	case *disable:
		return warpDisable(u)
	}
	warpStatus(u, *base)
	return 0
}

// startWarp runs the WARP profiles in the background and adds each to the race
// as soon as its port opens, so Connect is not held up by the scan Aether does
// first. It returns the note for the result box and the function that stops
// the processes.
func startWarp(ctx context.Context, o connectOptions, proxy *smartproxy.Proxy, dns *dnscheck.Result, t *term) (string, func()) {
	if o.noWarp {
		return "off (-no-warp)", func() {}
	}
	switch warpState(o.base) {
	case "no core", "no identity":
		return "off - optional: `ktest warp -enable` lets Telegram and sites blocked by address open", func() {}
	}
	var started []*runningCore
	var files []*os.File
	ech, echIP := "", ""
	if cfg, addr, err := front.FetchCloudflareECH(ctx); err == nil {
		ech, echIP = base64.StdEncoding.EncodeToString(cfg), addr
	}
	for i, p := range aetherProfiles(ech, echIP) {
		port := aetherBasePort + i
		if err := portFree(port); err != nil {
			t.Note("skipped %s: %v", p.Label, err)
			continue
		}
		logs := &tailBuffer{max: 8192}
		logPath := filepath.Join(warpDir(), fmt.Sprintf("aether-%d.log", i+1))
		if lf, err := os.Create(logPath); err == nil {
			files = append(files, lf)
			logs.tee = lf
		}
		if o.verbose {
			if logs.tee != nil {
				logs.tee = io.MultiWriter(logs.tee, os.Stderr)
			} else {
				logs.tee = os.Stderr
			}
		}
		cctx, cancel := context.WithCancel(ctx)
		rc := &runningCore{cancel: cancel, done: make(chan struct{})}
		l := aetherLauncher(aetherBinary(o.base), aetherRunArgs(i, p, port), logs)
		go func() {
			rc.err = l(cctx, dns)
			close(rc.done)
		}()
		started = append(started, rc)
		go func(p aetherProfile, port int, logs *tailBuffer, logPath string) {
			if !waitForPort(ctx, rc.done, port, 90*time.Second) {
				if ctx.Err() == nil {
					t.Line(toneWarn, "%s did not come up", p.Label)
					if rc.err != nil {
						t.Note("%v", rc.err)
					}
					for _, l := range logs.lastLines(3) {
						t.Note("%s", wrapOne(l, 150))
					}
					t.Note("full log: %s", logPath)
				}
				return
			}
			err := proxy.Add(smartproxy.Upstream{Name: p.Label, Addr: fmt.Sprintf("127.0.0.1:%d", port), Rank: 5, Exit: true, Late: true})
			if err == nil && ctx.Err() == nil {
				t.Line(toneOK, "%s is ready: Telegram and sites blocked by address can open now", p.Label)
			}
		}(p, port, logs, logPath)
	}
	stop := func() {
		for _, rc := range started {
			rc.cancel()
		}
		for _, rc := range started {
			rc.stop()
		}
		for _, f := range files {
			_ = f.Close()
		}
	}
	return "starting in the background (a scan comes first, up to a minute)", stop
}

// setup is the menu screen for the two optional pieces: the certificate that
// enables domain fronting and the WARP exit.
func (t *terminal) setup(base string, readLine func() (string, bool)) {
	u := t.ui
	for {
		u.Heading("setup", "Both are optional and can be removed again.")
		cert := map[string]string{
			"ok": "set up", "missing": "not set up", "outdated": "outdated: renew it", "untrusted": "not trusted yet",
		}[certState()]
		warp := map[string]string{"ready": "enabled", "no core": "off", "no identity": "core present, not registered"}[warpState(base)]
		u.Printf("  %s  %s  %s\n", u.Bold(u.Cyan("1")), u.Bold("Certificate"), u.Dim(cert+" (domain fronting: YouTube, X, Instagram, Reddit ...)"))
		u.Printf("  %s  %s  %s\n", u.Bold(u.Cyan("2")), u.Bold("WARP exit "), u.Dim(warp+" (Telegram and sites blocked by address)"))
		u.Printf("  %s  %s\n\n  Select > ", u.Bold(u.Cyan("0")), u.Bold("Back"))
		line, ok := readLine()
		if !ok {
			return
		}
		switch line {
		case "1":
			t.frontSetup(readLine)
		case "2":
			t.warpSetup(base, readLine)
		case "0", "b", "B":
			return
		case "":
		default:
			u.Line(toneWarn, "Unknown option. Select 1-2, or 0 to go back.")
		}
	}
}

func (t *terminal) warpSetup(base string, readLine func() (string, bool)) {
	u := t.ui
	warpStatus(u, base)
	if warpState(base) == "ready" {
		u.Printf("  Type REMOVE to delete the WARP identity, or press Enter to keep it > ")
		if ans, ok := readLine(); ok && strings.EqualFold(ans, "REMOVE") {
			warpDisable(u)
		}
		return
	}
	u.Printf("  Type YES to enable it (downloads the pinned Aether core if missing and registers a free anonymous WARP identity) > ")
	if ans, ok := readLine(); !ok || !strings.EqualFold(ans, "YES") {
		u.Line(toneInfo, "Cancelled; nothing was changed.")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	warpEnable(ctx, u, base)
}

// wrapOne shortens a log line to n runes.
func wrapOne(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}
