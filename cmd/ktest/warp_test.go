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

func TestFetchAetherVerifiesTheChecksumAndExtractsOnlyTheCore(t *testing.T) {
	data := zipOf(t, map[string]string{filepath.Base(aetherBinary("x")): "core", "pt/lyrebird.exe": "other", "../evil": "no"})
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
	entries, _ := os.ReadDir(filepath.Join(base, "cores"))
	if len(entries) != 1 {
		t.Fatalf("only the core may be extracted, got %d files", len(entries))
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

func TestAetherRunArgsNeverPromptAndStayOnLoopback(t *testing.T) {
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	for i, p := range aetherProfiles("CFG", "1.2.3.4") {
		args := strings.Join(aetherRunArgs(i, p, aetherBasePort+i), " ")
		// Protocol, scan mode, IP version and the reconnect question each have a flag.
		for _, want := range []string{"--masque", "--h2", "--turbo", "-4", "--quick-reconnect", "--masque-config"} {
			if !strings.Contains(args, want) {
				t.Errorf("profile %d lacks %s: %s", i, want, args)
			}
		}
		if !strings.Contains(args, "--bind 127.0.0.1:") {
			t.Errorf("profile %d must bind to loopback: %s", i, args)
		}
	}
	echo := false
	for _, p := range aetherProfiles("CFG", "1.2.3.4") {
		joined := strings.Join(p.Args, " ")
		if strings.Contains(joined, "--ech CFG") && strings.Contains(joined, "--no-fragment") && strings.Contains(joined, "--enroll-address 1.2.3.4") {
			echo = true
		}
	}
	if !echo {
		t.Fatal("an ECH profile with a fetched configuration and a known address is required for firewalls that close fragmentation and filter the API")
	}
}

func TestWarpStateAndRegisterOrder(t *testing.T) {
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
