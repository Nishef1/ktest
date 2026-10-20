package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAetherProgressShowsFragmentedNativeMilestonesWithoutCredentials(t *testing.T) {
	var shown []string
	w := &aetherProgress{show: func(s string) { shown = append(shown, s) }}
	for _, chunk := range []string{
		"[INFO aether] identity ready: device=private token=secret\n",
		"[INFO aether::prober] [*] scan mode=balanced ip=ipv4 candi",
		"dates=2011 ports=[443, 500] concurrency=16 per_probe=6s budget=120s\n",
		"[INFO aether] [+] selected MASQUE gateway 162.159.197.1:443 (rtt 120ms)\n",
		"[WARN aether] [-] scan deadline reached with no gateway\n",
	} {
		_, _ = w.Write([]byte(chunk))
	}
	if len(shown) != 3 || !strings.Contains(shown[0], "2011 candidates / 120s") ||
		!strings.Contains(shown[1], "162.159.197.1:443; HTTPS exit still unverified") ||
		!strings.Contains(w.stage(), "untested") {
		t.Fatalf("native scan stages were lost: %v", shown)
	}
	for _, s := range shown {
		if strings.Contains(s, "private") || strings.Contains(s, "secret") {
			t.Fatal("native identity leaked")
		}
	}
	if got := aetherMilestone("selected WireGuard endpoint token=secret"); got != "" {
		t.Fatalf("unvalidated endpoint reached UI: %s", got)
	}
}

func TestAetherProgressWaitsForFinalScanFailure(t *testing.T) {
	failures := 0
	w := &aetherProgress{show: func(string) {}, scanFailed: func() { failures++ }}
	w.Write([]byte("[WARN aether::prober] [-] scan deadline reached with no gateway\n"))
	if failures != 0 {
		t.Fatal("low-level scan message stopped possible native fallback")
	}
	for _, chunk := range []string{
		"[WARN aether] [-] no usable MASQUE gate",
		"way found: prober: no clean endpoint found; rescanning shortly\n",
		"[WARN aether] [-] no usable MASQUE gateway found: retry\n",
	} {
		w.Write([]byte(chunk))
	}
	if failures != 1 {
		t.Fatalf("final scan failure notifications = %d, want 1", failures)
	}
}

func TestAetherScanHelper(t *testing.T) {
	if os.Getenv("KTEST_SCAN_HELPER") != "1" {
		return
	}
	mode := (aetherProfile{Args: os.Args}).Value("--scan")
	fmt.Printf("[INFO aether::prober] scan mode=%s ip=ipv4 candidates=2013 budget=45s\n", mode)
	fmt.Println("[WARN aether::prober] [-] scan deadline reached with no gateway")
	fmt.Println("[WARN aether] [-] no usable MASQUE gateway found: prober: no clean endpoint found; rescanning shortly")
	time.Sleep(30 * time.Second) // native core would otherwise begin the same scan again
	os.Exit(0)
}

func TestAutomaticDiscoveryAdvancesWhenNativeScanFinishesWithoutGateway(t *testing.T) {
	t.Setenv("KTEST_SCAN_HELPER", "1")
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(aetherBinary(base)), 0700); err != nil {
		t.Fatal(err)
	}
	// Exercise the real managed process and readiness path without real keys,
	// an external tunnel, or network traffic outside loopback.
	if err := os.Link(os.Args[0], aetherBinary(base)); err != nil {
		data, readErr := os.ReadFile(os.Args[0])
		if readErr != nil {
			t.Fatal(readErr)
		}
		if err := os.WriteFile(aetherBinary(base), data, 0700); err != nil {
			t.Fatal(err)
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	i := l.Addr().(*net.TCPAddr).Port - aetherBasePort
	l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := os.WriteFile(identityFile(), enrollmentFixture(t, time.Now().Add(time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	p := recoveryProfile("scan helper", "-test.run=^TestAetherScanHelper$", "--", "--masque", "--h2")
	profiles := make([]aetherProfile, i+1)
	profiles[i] = p
	m := &warpManager{o: connectOptions{base: base, mode: ModeWindscribeAether}, t: plainTerm(&output), processCtx: ctx, profs: profiles, keyChecked: true}
	found := m.compare(ctx, 1, false, []int{i})
	if len(found) != 0 || ctx.Err() != nil || !strings.Contains(output.String(), "native gateway scan finished") {
		t.Fatalf("did not advance on completed failed scan: found=%d ctx=%v output=%s", len(found), ctx.Err(), output.String())
	}
	if !strings.Contains(output.String(), "gateway scan: turbo") || !m.attempted[p.ID()] || m.attempted[m.discoveryProfile(p).ID()] {
		t.Fatalf("quick launch lost its original profile/measurement identity: %s", output.String())
	}
}
