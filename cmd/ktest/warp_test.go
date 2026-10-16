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
	for _, want := range []string{"--quick-reconnect", "--bind 127.0.0.1:10830", "--masque-config", "--wg-config"} {
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

func TestLastGoodProfileGoesFirstAndWarpStateAndRegisterOrder(t *testing.T) {
	ps := []aetherProfile{{Label: "a"}, {Label: "b"}, {Label: "c"}}
	got := lastGoodFirst(ps, "c")
	if got[0].Label != "c" || got[1].Label != "a" || got[2].Label != "b" || len(got) != 3 {
		t.Fatalf("%v", got)
	}
	if got := lastGoodFirst(ps, "gone"); got[0].Label != "a" || len(got) != 3 {
		t.Fatalf("%v", got)
	}

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
	if warpState(base) != "ready" {
		t.Fatal(warpState(base))
	}
	with := registerAttempts(true, "B64", "1.2.3.4")
	if len(with) != 4 || with[0][0] != "--upstream" || with[1][0] != "--ech" || with[1][1] != "B64" || with[1][3] != "1.2.3.4" {
		t.Fatalf("the running ktest proxy must be tried first: %v", with)
	}
	if without := registerAttempts(false, "", ""); len(without) != 2 || without[0] != nil {
		t.Fatalf("%v", without)
	}
}
