package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// The WARP exit is the one path that does not depend on what a site's CDN
// accepts: Aether (an open-source Rust core, AGPL-3.0, run as a separate
// process like Xray and ByeDPI) tunnels MASQUE over HTTP/2 to Cloudflare WARP
// and serves SOCKS5. Traffic that uses it leaves from a Cloudflare address, so
// destinations that are blocked by address (Telegram) and sites that no front
// reaches open too. It is opt-in because it registers a free, anonymous WARP
// identity on this PC and sends the traffic that uses it through Cloudflare.
const (
	aetherVersion  = "v2.3.1"
	aetherZipSHA   = "a3bdd2384a624b01e9c4885f2816d75f7039fd2f62d46a94c54a0785e7c8fcb4"
	aetherBasePort = 10830
)

// aetherHasModernCLI distinguishes old v2.3.0 installations from the newer
// PattNG-aligned core without touching saved WARP identities. This is a
// compatibility check, not proof of network reachability or binary provenance.
func aetherHasModernCLI(ctx context.Context, binary string) bool {
	if !fileOK(binary) {
		return false
	}
	inspectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(inspectCtx, binary, "--help").Output()
	return err == nil && bytes.Contains(output, []byte("--api-address")) &&
		bytes.Contains(output, []byte("--masque-sni"))
}

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
	name := "psiphon-tunnel-core"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(base, "cores", "pt", name)
}

func aetherArchiveFor(goos, goarch string) (string, string, error) {
	name, sum := "", ""
	switch goos + "/" + goarch {
	case "windows/amd64":
		name, sum = "aether-windows-x86_64.zip", aetherZipSHA
	case "linux/amd64":
		name, sum = "aether-linux-x86_64.tar.gz", "371f92dcaa2b060bcd24e430f79d2b4864a38b3f7a76f1a05fd0692cc2c50a38"
	case "linux/arm64":
		name, sum = "aether-linux-arm64.tar.gz", "3725989e5a78dfccb821c66fb1204e3cc11ac0d3c9511e06d679f64b800ee2ab"
	case "darwin/amd64":
		name, sum = "aether-macos-x86_64.tar.gz", "10c89a252f51a3de5d3770ca2f2587400bb4565a11e692607a953f1ed9bdbbb1"
	case "darwin/arm64":
		name, sum = "aether-macos-arm64.tar.gz", "dfb7d24f8cadfff16f5dfbbf1b0007732a97f367763cced4c2efb54f46d5eb72"
	default:
		return "", "", fmt.Errorf("no checksum-pinned Aether %s archive for %s/%s", aetherVersion, goos, goarch)
	}
	return "https://github.com/patterniha/Aether/releases/download/" + aetherVersion + "/" + name, sum, nil
}

func identityFile() string          { return filepath.Join(warpDir(), "masque.toml") }
func wireguardIdentityFile() string { return filepath.Join(warpDir(), "wg.toml") }

// Credentials are checked offline; this never registers a device or proves a tunnel.
func warpState(base string) string {
	if !fileOK(aetherBinary(base)) {
		return "no core"
	}
	masque := checkWarpIdentity(identityFile(), "masque")
	wg := checkWarpIdentity(wireguardIdentityFile(), "wg")
	if masque == nil && wg == nil {
		return "ready"
	}
	if errors.Is(masque, os.ErrNotExist) && errors.Is(wg, os.ErrNotExist) {
		return "no identity"
	}
	return "partial"
}

// fetchAether verifies the pinned release and extracts Aether plus its
// whitelisted Psiphon/Lyrebird helpers into base/cores.
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
	// The release workflow packages aether and pt/ at archive root. Reject
	// every other entry, never extracting arbitrary filenames from the archive.
	core := filepath.Base(aetherBinary(base))
	ptBin := filepath.Base(psiphonCore(base))
	lyre := "lyrebird"
	if runtime.GOOS == "windows" {
		lyre += ".exe"
	}
	want := map[string]string{
		core:          aetherBinary(base),
		"pt/" + ptBin: psiphonCore(base),
		"pt/" + lyre:  filepath.Join(base, "cores", "pt", lyre),
	}
	found := false
	if bytes.HasPrefix(data, []byte{'P', 'K', 3, 4}) {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return err
		}
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
	} else if bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return err
		}
		defer zr.Close()
		tr := tar.NewReader(zr)
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
			name := strings.TrimPrefix(h.Name, "./")
			dest, ok := want[name]
			if !ok {
				continue
			}
			if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
				return fmt.Errorf("refusing non-regular Aether archive entry %s", name)
			}
			if h.Size < 0 || h.Size > 100<<20 {
				return fmt.Errorf("Aether archive entry %s exceeds size limit", name)
			}
			if err := extractVerifiedFile(tr, dest, h.Size); err != nil {
				return err
			}
			if name == core {
				found = true
			}
		}
	} else {
		return fmt.Errorf("unsupported Aether archive format")
	}
	if !found {
		return fmt.Errorf("the archive does not contain %s", core)
	}
	return nil
}

// Every file is published via an adjacent temporary path only after it is
// fully written; unsuccessful extraction never publishes half an executable.
func extractVerifiedFile(src io.Reader, dest string, size int64) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp := dest + ".part"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	n, err := io.CopyN(out, src, size)
	if err != nil || n != size {
		_ = out.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("incomplete executable %s: %w", filepath.Base(dest), err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func extractZipFile(f *zip.File, dest string) error {
	if f.FileInfo().Mode().IsRegular() && f.UncompressedSize64 <= 100<<20 {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		return extractVerifiedFile(rc, dest, int64(f.UncompressedSize64))
	}
	return fmt.Errorf("refusing non-regular or oversized Aether archive entry %s", f.Name)
}

// warpEnable makes the WARP exit available: the core, then the identity.
func warpEnable(ctx context.Context, u *term, base, proxy string) int {
	url, hash, err := aetherArchiveFor(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		u.Line(toneFail, "%v", err)
		return 1
	}
	if !aetherHasModernCLI(ctx, aetherBinary(base)) || !fileOK(psiphonCore(base)) {
		step := u.Progress("Installing or upgrading Aether "+aetherVersion, 1)
		if err := fetchAether(ctx, url, hash, base); err != nil {
			step.Finish(toneFail, err.Error())
			u.Note("Download %s yourself, check its SHA-256 (%s) and put the core plus pt/ helpers into %s.", url, hash, filepath.Join(base, "cores"))
			return 1
		}
		step.Finish(toneOK, "verified against the pinned SHA-256")
	}
	var routes []enrollmentRoute
	_, masqueErr := os.Stat(identityFile())
	_, wgErr := os.Stat(wireguardIdentityFile())
	if errors.Is(masqueErr, os.ErrNotExist) || errors.Is(wgErr, os.ErrNotExist) {
		routes = enrollmentRoutes(ctx, base, proxy, "", "")
	}
	failed := false
	for _, protocol := range []string{"masque", "wg"} {
		if err := enrollWarpIdentity(ctx, u, aetherBinary(base), protocol, routes, runEnrollment); err != nil {
			u.Line(toneWarn, "%s registration: %v", protocol, err)
			failed = true
		}
		if ctx.Err() != nil {
			u.Line(toneWarn, "Setup cancelled; saved identities were kept.")
			return 1
		}
	}
	if failed {
		u.Line(toneWarn, "Exit components installed; WARP setup is incomplete. Psiphon needs no WARP identity. Retry (y) here or `ktest warp -enable` when a registration route is available.")
		return 1
	}
	u.Line(toneOK, "MASQUE and WireGuard identities ready. Connect verifies the actual tunnels separately.")
	return 0
}

func warpDisable(u *term) int {
	dir := warpDir()
	if dir == "" {
		return 0
	}
	for _, path := range []string{identityFile(), wireguardIdentityFile(), filepath.Join(dir, "masque-secondary.toml"), filepath.Join(dir, "wg-secondary.toml"), filepath.Join(dir, "masque-gool.toml")} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			u.Line(toneFail, "cannot delete %s: %v", path, err)
			return 1
		}
	}
	u.Line(toneOK, "The WARP identities (including nested hops) were deleted. Core files and other settings were kept.")
	return 0
}

func warpStatus(u *term, base string) {
	u.Heading("exit paths", "WARP / Psiphon components and saved credentials. Actual tunnels are checked on Connect.")
	switch s := warpState(base); s {
	case "ready":
		u.Line(toneOK, "MASQUE and WireGuard identities are locally valid; tunnel unverified.")
	case "no identity", "partial":
		u.Line(toneWarn, "WARP registration incomplete; Psiphon does not need a WARP identity.")
	default:
		u.Line(toneInfo, "Off. `ktest warp -enable` downloads Aether %s (about 24 MB, pinned SHA-256) and tries to register a free anonymous WARP identity on this PC.", aetherVersion)
	}
	if warpState(base) != "no core" {
		for _, item := range []struct{ protocol, path string }{{"masque", identityFile()}, {"wg", wireguardIdentityFile()}} {
			if err := checkWarpIdentity(item.path, item.protocol); err != nil {
				u.Line(toneWarn, "%s identity: %v", item.protocol, err)
			} else {
				u.Line(toneOK, "%s identity: saved / locally valid", item.protocol)
			}
		}
	}
	u.Note("Initial registration uses HTTPS to the WARP API; a working gateway does not prove that registration is reachable.")
	u.Note("Saved keys are reused. ECH or Psiphon can carry initial registration; they do not guarantee access on every network.")
	u.Note("Gool and nested MASQUE/WireGuard prepare separate inner identities only when selected. Gool registers its inner key through the outer MASQUE tunnel.")
	u.Note("Portable folder updates keep the key directory %s. To survive removal of user data, use warp -backup / -restore with an encrypted file.", warpDir())
	u.Note("Traffic using these exits leaves through Cloudflare or Psiphon. When they join routing depends on the selected policy.")
	u.Note("Edit profiles/aether-profiles.txt to change what is tried; logs are in %s.", warpDir())
}

const warpUsage = `usage: ktest warp [-enable | -disable | -backup FILE | -restore FILE] [-base DIR]

  (no flag)   show the state of the exit paths
  -enable     download Aether if needed; prepare missing MASQUE and WireGuard identities
  -disable    delete the MASQUE and WireGuard identities (other settings are kept)
  -backup     save encrypted identities to a new file; hidden password prompt
  -restore    restore missing valid identities; never overwrite current keys
`

// runWarp is `ktest warp`.
func runWarp(args []string) int {
	fs := flag.NewFlagSet("warp", flag.ContinueOnError)
	base := fs.String("base", defaultBase(), "")
	enable := fs.Bool("enable", false, "")
	disable := fs.Bool("disable", false, "")
	backup := fs.String("backup", "", "")
	restore := fs.String("restore", "", "")
	fs.Usage = func() { fmt.Fprint(os.Stderr, warpUsage) }
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	u := newTerm(os.Stdout)
	active := 0
	for _, enabled := range []bool{*enable, *disable, *backup != "", *restore != ""} { if enabled { active++ } }
	if active > 1 {
		u.Line(toneFail, "Choose exactly one of -enable, -disable, -backup or -restore")
		return 2
	}
	switch {
	case *backup != "":
		return runWarpBackup(*backup, false, u)
	case *restore != "":
		return runWarpBackup(*restore, true, u)
	case *enable:
		return warpEnable(context.Background(), u, *base, connectListenDefault)
	case *disable:
		return warpDisable(u)
	}
	warpStatus(u, *base)
	return 0
}

// setup is the menu screen for the two optional pieces: the certificate that
// enables domain fronting and the WARP exit.
func (t *terminal) setup(base string, in *input) bool {
	u := t.ui
	message := ""
	for {
		u.menuView()
		u.Heading("setup", "Certificate health and optional exit components.")
		if message != "" {
			u.Line(toneWarn, "%s", message)
			message = ""
		}
		cert := inspectCertificate()
		u.menuOption("1", "Certificate", cert.summary(u))
		if cert.ca != nil {
			u.Note("Expires: %s", cert.ca.Expires().Format("2006-01-02"))
		}
		warp := map[string]string{"ready": "Identities valid / tunnel unverified", "no core": "Install exit components", "no identity": "Core present / WARP not registered", "partial": "WARP identities incomplete / repair or retry"}[warpState(base)]
		u.menuOption("2", "Exit paths", warp)
		u.Printf("\n")
		u.Note("Certificate: optional website fronting for Balanced / Fast.")
		u.Note("Exit components do not prove a working VPN. Windscribe uses its own app.")
		u.Note("No certificate changes without your choice.")
		u.Printf("\n")
		u.menuOption("0", "Back", backHint)
		u.Printf("\n  Select > ")
		line, ok := in.read()
		if !ok {
			return false
		}
		switch strings.ToLower(line) {
		case "1", "2":
			u.leaveMenu()
			var alive bool
			if line == "1" {
				alive = t.frontSetup(in.read)
			} else {
				alive = t.warpSetup(base, in.read)
			}
			if in.interrupted {
				in.interrupted = false
				continue
			}
			if !alive {
				return false
			}
		case "0", "b", "back":
			return true
		case "":
		default:
			message = "Select 1-2, or 0 to go back."
		}
	}
}

func (t *terminal) warpSetup(base string, readLine func() (string, bool)) bool {
	u := t.ui
	for {
		warpStatus(u, base)
		u.Printf("  y = prepare/retry missing identities; REMOVE = delete WARP identities; Enter / 0 = back > ")
		ans, ok := readLine()
		if !ok {
			return false
		}
		if ans == "" || isBackChoice(ans) {
			return true
		}
		if strings.EqualFold(ans, "REMOVE") {
			warpDisable(u)
			continue
		}
		if !isYes(ans) {
			u.Line(toneWarn, "Select y, REMOVE, or 0 to go back.")
			continue
		}
		u.Note("Press Ctrl+C to cancel setup.")
		if !t.foreground(func(ctx context.Context) {
			ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
			defer cancel()
			warpEnable(ctx, u, base, t.options.listen)
		}) {
			return false
		}
	}
}
