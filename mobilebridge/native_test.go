package mobilebridge

import (
	"context"
	"encoding/json"
	"testing"

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
		p, err := nativeProfile("psiphon", method)
		if err != nil || !p.Psiphon() {
			t.Fatalf("Psiphon acquired a non-Psiphon backend: %+v %v", p, err)
		}
	}
	if _, err := nativeProfile("psiphon", "masque-h2"); err == nil {
		t.Fatal("Psiphon selected a WARP route")
	}
	if _, err := nativeProfile("tor", "wireguard"); err == nil {
		t.Fatal("Tor selected a WireGuard route")
	}
	p, err := nativeProfile("tor", "auto")
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
