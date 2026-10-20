package mobilebridge

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Nishef1/ktest/internal/aether"
	"github.com/Nishef1/ktest/internal/coreprocess"
)

func TestNativeStartupCannotSubstituteAnotherModeOrMissingBundle(t *testing.T) {
	StopProxy()
	defer StopProxy()
	for _, mode := range []string{"balanced", "windscribe", "windscribe-aether", "unknown", "aether", "tor", "psiphon"} {
		if _, err := StartNativeProxy(mode, "auto", t.TempDir(), t.TempDir()); err == nil {
			t.Fatalf("native mode %s started without its verified bundle", mode)
		}
		var report proxyReport
		if err := json.Unmarshal([]byte(ProxyStatus()), &report); err != nil || report.Running {
			t.Fatalf("invalid native setup published a connection: %+v (%v)", report, err)
		}
		if coreprocess.Count() != 0 {
			t.Fatal("invalid native setup left a child process")
		}
	}
	if _, err := StartProxy("balanced"); err != nil {
		t.Fatalf("failed native setup prevented ordinary reconnect: %v", err)
	}
}

func TestNativeProfileSelectionPreservesTransportIsolation(t *testing.T) {
	for _, method := range []string{"auto", "psiphon", "psiphon-cdn"} {
		p, err := nativeProfile("psiphon", method, false)
		if err != nil || !p.Psiphon() {
			t.Fatalf("Psiphon acquired a non-Psiphon backend: %+v %v", p, err)
		}
	}
	if _, err := nativeProfile("psiphon", "masque-h2", false); err == nil {
		t.Fatal("Psiphon selected a WARP route")
	}
	if _, err := nativeProfile("tor", "wireguard", false); err == nil {
		t.Fatal("Tor selected a WireGuard route")
	}
	p, err := nativeProfile("tor", "auto", false)
	if err != nil || !p.Has("--tor-only") || p.Has("--tor") {
		t.Fatalf("Tor-only policy unexpectedly gained a WARP hop: %+v %v", p, err)
	}
}

func TestNativeWaitHonorsCancelAndDoesNotAdvertiseAnExitedCore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := waitNative(ctx, "aether", &nativeCore{done: make(chan struct{})}); err == nil {
		t.Fatal("canceled native startup became ready")
	}
	done := make(chan struct{})
	close(done)
	if _, err := waitNative(context.Background(), "tor", &nativeCore{done: done}); err == nil {
		t.Fatal("an exited native core became ready")
	}
}

func TestNativeVerificationRejectsCoreExitDuringSuccessfulProbe(t *testing.T) {
	for _, mode := range []string{"aether", "tor", "psiphon"} {
		t.Run(mode, func(t *testing.T) {
			done := make(chan struct{})
			core := &nativeCore{address: "127.0.0.1:12345", done: done}
			calls := 0
			got, err := waitNativeWithProbe(context.Background(), mode, core, func(_ context.Context, selectedMode, address string) (observedExit, error) {
				calls++
				if selectedMode != mode || address != core.address {
					t.Fatal("unexpected native probe arguments")
				}
				close(done)
				return observedExit{IP: "203.0.113.10", Region: "DE"}, nil
			})
			if err == nil || got.IP != "" || calls != 1 {
				t.Fatalf("exited native process was promoted after probe: %+v, %v, calls=%d", got, err, calls)
			}
		})
	}
}

func TestNativeVerificationRejectsCancellationDuringSuccessfulProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	core := &nativeCore{address: "127.0.0.1:12345", done: make(chan struct{})}
	got, err := waitNativeWithProbe(ctx, "aether", core, func(context.Context, string, string) (observedExit, error) {
		cancel()
		return observedExit{IP: "203.0.113.10"}, nil
	})
	if err == nil || got.IP != "" {
		t.Fatalf("canceled native startup was promoted: %+v, %v", got, err)
	}
}

func TestNativeVerificationPromotesHealthyProcess(t *testing.T) {
	core := &nativeCore{address: "127.0.0.1:12345", done: make(chan struct{})}
	got, err := waitNativeWithProbe(context.Background(), "psiphon", core, func(context.Context, string, string) (observedExit, error) {
		return observedExit{IP: "203.0.113.10", Region: "DE"}, nil
	})
	if err != nil || got.IP != "203.0.113.10" {
		t.Fatalf("healthy verified core was rejected: %+v, %v", got, err)
	}
}

func TestAetherThroughFastOnlyUsesTCPMethods(t *testing.T) {
	p, err := nativeProfile("aether", "auto", true)
	if err != nil || !p.Has("--h2") || p.Has("--wg") || p.Psiphon() {
		t.Fatalf("automatic Fast-carried profile is not an H2 method: %v %v", p.Args, err)
	}
	for _, method := range []string{"masque-h2", "gool-h2", "mim-h2"} {
		if _, err := nativeProfile("aether", method, true); err != nil {
			t.Fatalf("%s should be carried by Fast: %v", method, err)
		}
	}
	for _, method := range []string{"masque-h3", "wireguard", "psiphon", "psiphon-cdn"} {
		if _, err := nativeProfile("aether", method, true); err == nil {
			t.Fatalf("%s needs UDP or its own helper and must be refused through Fast", method)
		}
	}
}

func TestAndroidAutoTriesIndependentWarpTransportsOnly(t *testing.T) {
	direct, err := nativeAutoCandidates(false)
	if err != nil || len(direct) < 3 {
		t.Fatalf("Auto lost independent H2, H3 and WireGuard methods: %v, %v", direct, err)
	}
	seen := map[string]bool{}
	for _, profile := range direct {
		if profile.Psiphon() || profile.Has("--tor-only") {
			t.Fatalf("strict Aether Auto unexpectedly switched to another backend: %v", profile.Args)
		}
		seen[profile.Method()] = true
	}
	for _, method := range []string{"masque-h2", "masque-h3", "wireguard"} {
		if !seen[method] {
			t.Fatalf("Aether Auto omitted independent %s route", method)
		}
	}
	carried, err := nativeAutoCandidates(true)
	if err != nil || len(carried) == 0 {
		t.Fatalf("Auto over Fast lost TCP candidates: %v", err)
	}
	for _, profile := range carried {
		if !profile.Has("--h2") || profile.Has("--wg") || profile.Psiphon() || profile.Has("--tor-only") {
			t.Fatalf("TCP-only Fast carrier selected unsupported method %v", profile.Args)
		}
	}
}

func TestAndroidAutoECHProfilesKeepDirectFallbackAndTransportIsolation(t *testing.T) {
	withECH, err := nativeAutoCandidatesWithECH(false, "valid-config", "162.159.197.1")
	if err != nil {
		t.Fatal(err)
	}
	var ech, fallback int
	for _, p := range withECH {
		if p.Psiphon() || p.Has("--tor-only") {
			t.Fatalf("ECH method discovery crossed Aether's exit-only boundary: %v", p.Args)
		}
		if p.Has("--ech") {
			ech++
			if p.Value("--ech") == "auto" {
				// Aether 2.3.1 can fetch the ECH configuration itself,
				// independent of our optional three-second lookup.
				if p.Has("--api-address") {
					t.Fatalf("core-managed ECH must not accidentally pin an API address: %v", p.Args)
				}
			} else if p.Value("--api-address") != "162.159.197.1" {
				t.Fatalf("pinned ECH profile omitted its API endpoint: %v", p.Args)
			}
		} else {
			fallback++
		}
	}
	if ech == 0 || fallback == 0 {
		t.Fatalf("ECH-only catalog has no connection fallback: ECH=%d direct=%d", ech, fallback)
	}
	firstMethods := map[string]bool{}
	for _, p := range withECH[:min(3, len(withECH))] {
		if p.Has("--ech") || firstMethods[p.Method()] {
			t.Fatalf("Android Auto spent its first startup attempts on duplicate/ECH variants: %v", p.Args)
		}
		firstMethods[p.Method()] = true
	}
	for _, method := range []string{"masque-h2", "masque-h3", "wireguard"} {
		if !firstMethods[method] {
			t.Fatalf("independent transport %s is starved behind slow variants", method)
		}
	}
	carried, err := nativeAutoCandidatesWithECH(true, "valid-config", "162.159.197.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range carried {
		if !aether.CanCarryLocally(p) {
			t.Fatalf("TCP-only Fast carrier was given UDP method %s", p.Method())
		}
	}
}
