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

// psiphonCore is the helper Aether runs for its Psiphon profiles; it must
// sit in a pt folder next to aether.exe.
func psiphonCore(base string) string {
	return filepath.Join(base, "cores", "pt", "psiphon-tunnel-core.exe")
}

func identityFile() string { return filepath.Join(warpDir(), "masque.toml") }

// warpState reports "no core" (the exit paths are off), "no identity" (the core
// is there, no WARP identity yet; Psiphon needs none and the others register on
// demand) or "ready".
func warpState(base string) string {
	switch {
	case !fileOK(aetherBinary(base)):
		return "no core"
	case !fileOK(identityFile()):
		return "no identity"
	}
	return "ready"
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
	// Only these files are used; anything else in the archive, and any path
	// that is not exactly one of them, is ignored.
	core := filepath.Base(aetherBinary(base))
	want := map[string]string{
		core:                         aetherBinary(base),
		"pt/psiphon-tunnel-core.exe": filepath.Join(base, "cores", "pt", "psiphon-tunnel-core.exe"),
		"pt/lyrebird.exe":            filepath.Join(base, "cores", "pt", "lyrebird.exe"),
	}
	found := false
	for _, f := range zr.File {
		dest, ok := want[f.Name]
		if !ok {
			continue
		}
		if err := extractZipFile(f, dest); err != nil {
			return err
		}
		if f.Name == core {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("the archive does not contain %s", core)
	}
	return nil
}

func extractZipFile(f *zip.File, dest string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp := dest + ".part"
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
	return os.Rename(tmp, dest)
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
	if !fileOK(aetherBinary(base)) || !fileOK(psiphonCore(base)) {
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
			u.Line(toneWarn, "%v", err)
			u.Note("No WARP identity yet. That is not fatal: the Psiphon profile needs none, and the WARP profiles try to register themselves with the ECH route each time.")
		}
	}
	u.Line(toneOK, "The exit paths are enabled. Connect searches for the one that works on this network in the background; Telegram and sites blocked by address open through it.")
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
	u.Heading("exit paths", "WARP and Psiphon leave from another address, so what is blocked by address (Telegram) opens too.")
	switch s := warpState(base); s {
	case "ready":
		u.Line(toneOK, "Enabled: Connect searches for the profiles that work here, in the background.")
		u.Note("WARP identity %s", identityFile())
	case "no identity":
		u.Line(toneOK, "Enabled (no WARP identity yet): Psiphon needs none, the WARP profiles register themselves or `ktest warp -enable` tries again.")
	default:
		u.Line(toneInfo, "Off. `ktest warp -enable` downloads Aether %s (about 24 MB, pinned SHA-256) and tries to register a free anonymous WARP identity on this PC.", aetherVersion)
	}
	u.Note("Traffic that uses them goes through Cloudflare or Psiphon. They are the last resort: they join a connection only after the other paths failed or took more than 3 seconds.")
	u.Note("Edit profiles/aether-profiles.txt to change what is tried; logs are in %s.", warpDir())
}

const warpUsage = `usage: ktest warp [-enable | -disable] [-base DIR]

  (no flag)   show the state of the exit paths
  -enable     download the Aether core if needed and try to register a WARP identity
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

// setup is the menu screen for the two optional pieces: the certificate that
// enables domain fronting and the WARP exit.
func (t *terminal) setup(base string, readLine func() (string, bool)) {
	u := t.ui
	for {
		u.Heading("setup", "Prepare optional capabilities. Configured files/identity do not prove a working connection.")
		u.Note("Certificate: HTTPS website fronting for Balanced/Fast (including their Whole PC coverage); it cannot authenticate or front raw OpenVPN.")
		u.Note("Exit paths: used by Balanced/Fast/Aether/Psiphon. Windscribe prohibits them; Aether to Tor uses its separately verified Tor route.")
		cert := map[string]string{
			"ok": "set up", "missing": "not set up", "outdated": "outdated: renew it", "untrusted": "not trusted yet",
		}[certState()]
		warp := map[string]string{"ready": "configured; tunnel unverified", "no core": "off", "no identity": "core present, not registered"}[warpState(base)]
		u.Printf("  %s  %s  %s\n", u.Bold(u.Cyan("1")), u.Bold("Certificate"), u.Dim(cert+" (domain fronting: YouTube, X, Instagram, Reddit ...)"))
		u.Printf("  %s  %s  %s\n", u.Bold(u.Cyan("2")), u.Bold("Exit paths"), u.Dim(warp+" (WARP, Psiphon: Telegram and sites blocked by address)"))
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
