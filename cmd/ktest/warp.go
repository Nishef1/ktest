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

	"github.com/Nishef1/ktest/internal/aether"
)

// The WARP exit is the one path that does not depend on what a site's CDN
// accepts: Aether (an open-source Rust core, AGPL-3.0, run as a separate
// process like Xray and ByeDPI) tunnels MASQUE over HTTP/2 to Cloudflare WARP
// and serves SOCKS5. Traffic that uses it leaves from a Cloudflare address, so
// destinations that are blocked by address (Telegram) and sites that no front
// reaches open too. It is opt-in because it registers a free, anonymous WARP
// identity on this PC and sends the traffic that uses it through Cloudflare.
const aetherBasePort = 10830

var aetherVersion = aether.DesktopVersion()

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

func aetherName() string {
	if runtime.GOOS == "windows" {
		return "aether.exe"
	}
	return "aether"
}
func psiphonName() string {
	if runtime.GOOS == "windows" {
		return "psiphon-tunnel-core.exe"
	}
	return "psiphon-tunnel-core"
}
func lyrebirdName() string {
	if runtime.GOOS == "windows" {
		return "lyrebird.exe"
	}
	return "lyrebird"
}
func aetherVersionDir(base string) string {
	return filepath.Join(base, "cores", "aether-versions", aetherVersion)
}
func aetherVersionReady(base string) bool {
	_, digest, err := aether.DesktopArchiveFor(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return false
	}
	dir := aetherVersionDir(base)
	marker, err := os.ReadFile(filepath.Join(dir, "aether-release.sha256"))
	if err != nil || strings.TrimSpace(string(marker)) != digest {
		return false
	}
	return fileOK(filepath.Join(dir, aetherName())) &&
		fileOK(filepath.Join(dir, "pt", psiphonName())) &&
		fileOK(filepath.Join(dir, "pt", lyrebirdName()))
}
// An explicit operator override allows immediate rollback if an upgraded
// executable starts but fails on a particular ISP. This changes selection
// only; no binary, helper, or saved WARP key is deleted.
func aetherUseLegacy(base string) bool {
	return os.Getenv("KTEST_AETHER_USE_LEGACY") == "1" &&
		fileOK(filepath.Join(base, "cores", aetherName()))
}
func aetherBinary(base string) string {
	if !aetherUseLegacy(base) && aetherVersionReady(base) {
		return filepath.Join(aetherVersionDir(base), aetherName())
	}
	return filepath.Join(base, "cores", aetherName())
}
func psiphonCore(base string) string {
	if !aetherUseLegacy(base) && aetherVersionReady(base) {
		return filepath.Join(aetherVersionDir(base), "pt", psiphonName())
	}
	return filepath.Join(base, "cores", "pt", psiphonName())
}
func aetherArchiveFor(goos, goarch string) (string, string, error) {
	return aether.DesktopArchiveFor(goos, goarch)
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
	if aetherVersionReady(base) {
		return nil
	}
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, (200<<20)+1))
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > 200<<20 {
		return errors.New("Aether archive empty or too large")
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, sha) {
		return fmt.Errorf("checksum mismatch: got %s, pinned %s; the file was not used", got, sha)
	}
	// Stage a complete generation alongside the running old core. Nothing
	// in the existing core directory is overwritten by partial downloads.
	parent := filepath.Dir(aetherVersionDir(base))
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".aether-staging-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	core, ptBin, lyre := aetherName(), psiphonName(), lyrebirdName()
	want := map[string]string{
		core:          filepath.Join(stage, core),
		"pt/" + ptBin: filepath.Join(stage, "pt", ptBin),
		"pt/" + lyre:  filepath.Join(stage, "pt", lyre),
	}
	seen := make(map[string]bool)
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
			if seen[f.Name] {
				return fmt.Errorf("duplicate Aether member %s", f.Name)
			}
			seen[f.Name] = true
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
			if seen[name] {
				return fmt.Errorf("duplicate Aether member %s", name)
			}
			seen[name] = true
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
		return fmt.Errorf("Aether archive missing %s", core)
	}
	for name := range want {
		if !seen[name] {
			return fmt.Errorf("Aether archive missing %s; previous core preserved", name)
		}
	}
	if err := os.WriteFile(filepath.Join(stage, "aether-release.sha256"), []byte(strings.ToLower(sha)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(stage, aetherVersionDir(base)); err != nil {
		if aetherVersionReady(base) {
			return nil
		}
		return fmt.Errorf("cannot publish Aether generation (previous core preserved): %w", err)
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
	if !aetherVersionReady(base) {
		step := u.Progress("Installing or upgrading Aether "+aetherVersion, 1)
		if err := fetchAether(ctx, url, hash, base); err != nil {
			// Setup must not turn an already-working legacy core into an
			// offline installation failure. Continue with its saved keys.
			if !aetherHasModernCLI(ctx, aetherBinary(base)) || !fileOK(psiphonCore(base)) {
				step.Finish(toneFail, err.Error())
				u.Note("Download %s yourself and check its SHA-256 (%s); your existing identities were preserved.", url, hash)
				return 1
			}
			step.Finish(toneWarn, "Upgrade unavailable; using compatible legacy Aether without deleting any keys")
		} else {
			step.Finish(toneOK, "verified against the pinned SHA-256")
		}
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

// Explicit updates are opt-in and never erase an already working core. The
// new executable is selected only after its complete generation is installed.
func warpUpgrade(ctx context.Context, u *term, base string) int {
	if aetherVersionReady(base) {
		u.Line(toneOK, "Aether %s is already installed and selected.", aetherVersion)
		return 0
	}
	url, digest, err := aetherArchiveFor(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		u.Line(toneFail, "%v", err)
		return 1
	}
	step := u.Progress("Staging Aether "+aetherVersion+" without touching active cores or WARP identities", 1)
	if err := fetchAether(ctx, url, digest, base); err != nil {
		step.Finish(toneFail, err.Error())
		u.Note("Previous Aether executable and all WARP identities were kept.")
		return 1
	}
	if !aetherHasModernCLI(ctx, aetherBinary(base)) {
		step.Finish(toneWarn, "new archive published but core CLI health check failed; stop and inspect")
		return 1
	}
	step.Finish(toneOK, "Aether "+aetherVersion+" staged, complete and CLI compatible")
	u.Note("Existing sessions keep their old process; connect again to select this version.")
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
	if aetherUseLegacy(base) {
		u.Line(toneWarn, "Legacy Aether selected by KTEST_AETHER_USE_LEGACY=1; v%s generation is not used in this process.", strings.TrimPrefix(aetherVersion, "v"))
	}
	if aetherVersionReady(base) {
		u.Line(toneOK, "Aether release %s installed (verified archive marker and all helpers).", aetherVersion)
	} else if fileOK(aetherBinary(base)) {
		u.Line(toneWarn, "Legacy Aether is available; use `ktest warp -upgrade` to stage %s without replacing it.", aetherVersion)
	}
	u.Note("Initial registration uses HTTPS to the WARP API; a working gateway does not prove that registration is reachable.")
	u.Note("Saved keys are reused. ECH or Psiphon can carry initial registration; they do not guarantee access on every network.")
	u.Note("Gool and nested MASQUE/WireGuard prepare separate inner identities only when selected. Gool registers its inner key through the outer MASQUE tunnel.")
	u.Note("Portable folder updates keep the key directory %s. To survive removal of user data, use warp -backup / -restore with an encrypted file.", warpDir())
	u.Note("Traffic using these exits leaves through Cloudflare or Psiphon. When they join routing depends on the selected policy.")
	u.Note("Edit profiles/aether-profiles.txt to change what is tried; logs are in %s.", warpDir())
}

const warpUsage = `usage: ktest warp [-enable | -upgrade | -disable | -backup FILE | -restore FILE] [-base DIR]

  (no flag)   show the state of the exit paths
  -enable     stage pinned Aether if needed; prepare missing MASQUE and WireGuard identities
  -upgrade    stage the latest SHA-pinned Aether generation; keep old core and identities
  -disable    delete the MASQUE and WireGuard identities (other settings are kept)
  -backup     save encrypted identities to a new file; hidden password prompt
  -restore    restore missing valid identities; never overwrite current keys
`

// runWarp is `ktest warp`.
func runWarp(args []string) int {
	fs := flag.NewFlagSet("warp", flag.ContinueOnError)
	base := fs.String("base", defaultBase(), "")
	enable := fs.Bool("enable", false, "")
	upgrade := fs.Bool("upgrade", false, "")
	disable := fs.Bool("disable", false, "")
	backup := fs.String("backup", "", "")
	restore := fs.String("restore", "", "")
	fs.Usage = func() { fmt.Fprint(os.Stderr, warpUsage) }
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	u := newTerm(os.Stdout)
	active := 0
	for _, enabled := range []bool{*enable, *upgrade, *disable, *backup != "", *restore != ""} {
		if enabled {
			active++
		}
	}
	if active > 1 {
		u.Line(toneFail, "Choose exactly one of -enable, -upgrade, -disable, -backup or -restore")
		return 2
	}
	switch {
	case *backup != "":
		return runWarpBackup(*backup, false, u)
	case *restore != "":
		return runWarpBackup(*restore, true, u)
	case *upgrade:
		return warpUpgrade(context.Background(), u, *base)
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
				alive = t.warpSetup(base, in)
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

func (t *terminal) warpSetup(base string, in *input) bool {
	u := t.ui
	for {
		warpStatus(u, base)
		u.Printf("  y = prepare/retry missing identities; u = upgrade Aether; REMOVE = delete WARP identities; Enter / 0 = back > ")
		ans, ok := in.read()
		if !ok {
			return false
		}
		if ans == "" || isBackChoice(ans) {
			return true
		}
		if strings.EqualFold(ans, "u") || strings.EqualFold(ans, "upgrade") {
			if !t.foreground(func(ctx context.Context) {
				ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
				defer cancel()
				warpUpgrade(ctx, u, base)
			}, in.enter()) {
				return false
			}
			continue
		}
		if strings.EqualFold(ans, "REMOVE") {
			warpDisable(u)
			continue
		}
		if !isYes(ans) {
			u.Line(toneWarn, "Select y, u, REMOVE, or 0 to go back.")
			continue
		}
		u.Note("Press Enter to cancel setup.")
		if !t.foreground(func(ctx context.Context) {
			ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
			defer cancel()
			warpEnable(ctx, u, base, t.options.listen)
		}, in.enter()) {
			return false
		}
	}
}
