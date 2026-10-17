package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestFetchAetherVerifiesTheChecksumAndExtractsOnlyKnownFiles(t *testing.T) {
	data := zipOf(t, map[string]string{
		filepath.Base(aetherBinary("x")): "core", "pt/psiphon-tunnel-core.exe": "psiphon", "pt/lyrebird.exe": "lyre",
		"pt/other.exe": "no", "../evil": "no", "run-aether.bat": "no",
	})
	sum := sha256.Sum256(data)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(data) }))
	defer srv.Close()

	base := t.TempDir()
	if err := fetchAether(context.Background(), srv.URL, strings.Repeat("0", 64), base); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("a wrong checksum was accepted: %v", err)
	}
	if fileOK(aetherBinary(base)) {
		t.Fatal("an unverified file was written")
	}
	if err := fetchAether(context.Background(), srv.URL, hex.EncodeToString(sum[:]), base); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(aetherBinary(base)); string(b) != "core" {
		t.Fatalf("core content %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(base, "cores", "pt", "psiphon-tunnel-core.exe")); string(b) != "psiphon" {
		t.Fatalf("psiphon core %q", b)
	}
	var names []string
	filepath.WalkDir(filepath.Join(base, "cores"), func(p string, d os.DirEntry, _ error) error {
		if !d.IsDir() {
			names = append(names, d.Name())
		}
		return nil
	})
	if len(names) != 3 {
		t.Fatalf("only the three known files may be extracted, got %v", names)
	}

	// An archive without the core is refused even with a matching checksum.
	empty := zipOf(t, map[string]string{"readme.txt": "x"})
	esum := sha256.Sum256(empty)
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(empty) }))
	defer srv2.Close()
	if err := fetchAether(context.Background(), srv2.URL, hex.EncodeToString(esum[:]), t.TempDir()); err == nil {
		t.Fatal("archive without the core accepted")
	}
}

func TestDefaultProfilesCoverTheTransportsAndSkipWhatNeedsECH(t *testing.T) {
	all, err := parseAetherProfiles(defaultAetherProfiles, "CFG", "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, p := range all {
		joined += strings.Join(p.Args, " ") + "\n"
	}
	// HTTP/2 and HTTP/3 MASQUE, WireGuard, IPv6 and Psiphon: networks differ in
	// which of them gets through.
	for _, want := range []string{"--h2", "--h3", "--wg", "-6", "--psiphon-only", "--ech CFG", "--enroll-address 1.2.3.4", "--api-fragment"} {
		if !strings.Contains(joined, want) {
			t.Errorf("default profiles lack %q", want)
		}
	}
	// Without a fetched configuration only the lines that do not need it remain,
	// and Psiphon, which needs neither the key nor WARP, is among them.
	few, err := parseAetherProfiles(defaultAetherProfiles, "", "")
	if err != nil {
		t.Fatal(err)
	}
	psiphon := 0
	for _, p := range few {
		if strings.Contains(strings.Join(p.Args, " "), "{ECH") {
			t.Fatalf("placeholder left in %v", p)
		}
		if p.psiphon() {
			psiphon++
		}
	}
	if len(few) >= len(all) || psiphon == 0 {
		t.Fatalf("%d of %d profiles remain without ECH, %d Psiphon", len(few), len(all), psiphon)
	}
	for _, bad := range []string{"no separator", "x | --bind 0.0.0.0:1", "x | --masque\nx | --wg"} {
		if _, err := parseAetherProfiles(bad, "", ""); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestAetherRunArgsNeverPromptStayOnLoopbackAndDoNotRepeatFlags(t *testing.T) {
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	p := aetherProfile{Label: "x", Args: []string{"--masque", "--h2", "--scan", "thorough", "-6", "--startup-secs", "100"}}
	args := strings.Join(aetherRunArgs(0, p, 10830), " ")
	for _, want := range []string{"--no-quick-reconnect", "--bind 127.0.0.1:10830", "--masque-config", "--wg-config"} {
		if !strings.Contains(args, want) {
			t.Errorf("lacks %s: %s", want, args)
		}
	}
	for _, dup := range []string{"--turbo", "-4", "--startup-secs 45"} {
		if strings.Contains(args, dup) {
			t.Errorf("repeats a flag the profile sets (%s): %s", dup, args)
		}
	}
	plain := strings.Join(aetherRunArgs(1, aetherProfile{Label: "y", Args: []string{"--masque"}}, 10831), " ")
	for _, want := range []string{"-4", "--turbo", "--startup-secs 45"} {
		if !strings.Contains(plain, want) {
			t.Errorf("default %s missing: %s", want, plain)
		}
	}
	ps := strings.Join(aetherRunArgs(2, aetherProfile{Label: "p", Args: []string{"--psiphon-only"}}, 10832), " ")
	if strings.Contains(ps, "--turbo") || strings.Contains(ps, "--quick-reconnect") || !strings.Contains(ps, "--bind 127.0.0.1:10832") {
		t.Errorf("psiphon args: %s", ps)
	}
}

func TestPsiphonModeSelectsOnlyPsiphonProfiles(t *testing.T) {
	base := t.TempDir()
	profiles, err := loadAetherProfiles(base, "CFG", "1.2.3.4", ModePsiphon)
	if err != nil || len(profiles) != 2 {
		t.Fatalf("default Psiphon profiles: %v, %v", profiles, err)
	}
	for _, p := range profiles {
		if !p.psiphon() {
			t.Fatalf("non-Psiphon profile selected: %v", p)
		}
	}
	if err := os.MkdirAll(filepath.Join(base, "profiles"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		"warp | --masque --h2\ntor | --tor-only\nmixed | --psiphon-only --wg\n",
		"cdn | --psiphon-only --psiphon-mode cdn\nwarp | --masque --h2\n",
	} {
		if err := os.WriteFile(aetherProfilesFile(base), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		profiles, err := loadAetherProfiles(base, "CFG", "1.2.3.4", ModePsiphon)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(text, "warp") && len(profiles) != 0 {
			t.Fatalf("Psiphon mode fell back to another transport: %v", profiles)
		}
		if strings.HasPrefix(text, "cdn") && (len(profiles) != 1 || profiles[0].Label != "cdn") {
			t.Fatalf("custom Psiphon profile not respected: %v", profiles)
		}
	}
}

func TestWarpState(t *testing.T) {
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	base := t.TempDir()
	if warpState(base) != "no core" {
		t.Fatal(warpState(base))
	}
	os.MkdirAll(filepath.Join(base, "cores"), 0o755)
	os.WriteFile(aetherBinary(base), []byte("x"), 0o755)
	if warpState(base) != "no identity" {
		t.Fatal(warpState(base))
	}
	os.WriteFile(identityFile(), []byte("x"), 0o600)
	if warpState(base) != "partial" {
		t.Fatal(warpState(base))
	}
}

func TestWindscribeCannotLaunchAetherOrPsiphon(t *testing.T) {
	note, stop := startWarp(context.Background(), connectOptions{mode: ModeWindscribe}, nil, nil, nil)
	if stop == nil {
		t.Fatal("expected no-op teardown")
	}
	defer stop()
	if !strings.Contains(note(), "prohibited") {
		t.Fatalf("Aether not rejected: %s", note())
	}
}

func TestExitStatusUpdatesDuringSearchAndDeadCoreIsRemovedImmediately(t *testing.T) {
	p, err := smartproxy.New(smartproxy.Config{ExitOnly: func(string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	m := &warpManager{proxy: p, t: plainTerm(&output)}
	m.searching.Store(true)
	status := m.status
	if !strings.Contains(status(), "0 exits available") {
		t.Fatal(status())
	}
	if err := p.Add(smartproxy.Upstream{Name: "Exit: test", Exit: true, AIEligible: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status(), "1 exit available") || !strings.Contains(status(), "search continuing") {
		t.Fatal(status())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rc := &runningCore{done: make(chan struct{})}
	finished := make(chan struct{})
	go func() { m.watchExit(ctx, "test", rc); close(finished) }()
	close(rc.done)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("dead exit remained registered while search was active")
	}
	if total, _ := p.ExitCounts(); total != 0 {
		t.Fatal(status())
	}
	m.searching.Store(false)
	if !strings.Contains(status(), "retry pending") {
		t.Fatal(status())
	}
}

func TestAetherHelpOptionMatchingAndEqualsValues(t *testing.T) {
	help := "  --help                 Print help\n  --h2, --http2          HTTP/2\n  --startup-secs <n>     Deadline\n  --config <file>       Config\n  --tls-verify           Certificate option\n"
	known := aetherDocumentedOptions(help)
	for _, option := range []string{"--help", "--h2", "--http2", "--startup-secs", "--config", "--tls-verify"} {
		if !known[option] {
			t.Errorf("missing documented %s", option)
		}
	}
	for _, invalid := range []string{"--h", "--tls", "--start", "--config-path"} {
		if known[invalid] {
			t.Errorf("substring accepted as option: %s", invalid)
		}
	}
	p := aetherProfile{Label: "custom", Args: []string{"--masque", "--startup-secs=100", "--ech=one"}}
	if !p.has("--startup-secs") || p.value("--startup-secs") != "100" || !p.has("--ech") {
		t.Fatal("equals-form flags were not parsed")
	}
	other := aetherProfile{Label: "custom", Args: []string{"--masque", "--startup-secs=100", "--ech=two"}}
	if p.id() != other.id() {
		t.Fatal("ECH session material should not destabilize profile identities")
	}
	for _, reserved := range []string{"--config=foo", "--bind=0.0.0.0:5"} {
		if _, err := parseAetherProfiles("bad | --masque "+reserved, "", ""); err == nil {
			t.Fatalf("reserved argument accepted: %s", reserved)
		}
	}
}
