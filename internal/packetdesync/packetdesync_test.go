package packetdesync

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCanceledStartupWaitsForOwnedProcessExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopping := make(chan struct{})
	trial := &Trial{ctx: ctx, cancel: func() { close(stopping) }, done: make(chan error, 1)}
	result := make(chan error, 1)
	go func() { result <- trial.awaitStartup(ctx) }()
	cancel()
	<-stopping
	select {
	case err := <-result:
		t.Fatalf("startup returned before its process exited: %v", err)
	default:
	}
	trial.done <- errors.New("process killed")
	if err := <-result; !errors.Is(err, context.Canceled) || errors.Is(err, ErrCleanupUnconfirmed) {
		t.Fatalf("confirmed cancellation was treated as unsafe cleanup: %v", err)
	}
}

func TestStopAcceptsReapedProcessAfterContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	trial := &Trial{ctx: ctx, cancel: cancel, done: make(chan error, 1)}
	trial.done <- errors.New("process killed")
	if err := trial.Stop(); err != nil {
		t.Fatalf("reaped cancellation blocked future trials: %v", err)
	}
}

func TestStopRejectsUnexpectedProcessExitWithLiveContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	trial := &Trial{ctx: ctx, cancel: cancel, done: make(chan error, 1)}
	trial.done <- errors.New("driver failed")
	if err := trial.Stop(); err == nil {
		t.Fatal("unexpected driver exit accepted as intentional cancellation")
	}
}

func TestCleanupTimeoutIsDistinguishableFromCancellation(t *testing.T) {
	trial := &Trial{cancel: func() {}, done: make(chan error, 1)}
	if err := trial.stopAndWait(time.Millisecond); !errors.Is(err, ErrCleanupUnconfirmed) {
		t.Fatalf("unconfirmed cleanup cannot be distinguished from a safe cancellation: %v", err)
	}
}

func TestTargetExactPacketFilterAndPresets(t *testing.T) {
	for _, preset := range []Strategy{Fake, Split, Combo} {
		t.Run(string(preset), func(t *testing.T) {
			filter, args, err := Target("198.51.100.23", preset)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(filter, "ip.DstAddr == 198.51.100.23") ||
				!strings.Contains(filter, "ip.SrcAddr == 198.51.100.23") ||
				!strings.Contains(filter, "tcp.DstPort == 443") ||
				!strings.Contains(filter, "tcp.SrcPort == 443") ||
				!strings.Contains(filter, "!loopback") || !strings.Contains(filter, "!impostor") {
				t.Fatalf("filter widened unexpectedly: %s", filter)
			}
			if len(args) < 8 || len(args) > 9 || args[0] != "--wf-raw="+filter ||
				strings.Contains(strings.Join(args, " "), "--wf-raw-part") ||
				strings.Contains(strings.Join(args, " "), "--wf-tcp-out") {
				t.Fatalf("unsafe or malformed WinDivert arguments: %q", args)
			}
		})
	}
}

func TestTargetRejectsUnscopedOrPrivateAddresses(t *testing.T) {
	for _, target := range []string{
		"", "google.com", "127.0.0.1", "0.0.0.0",
		"10.0.0.1", "192.168.1.4", "169.254.1.1",
		"::1", "2001:4860:4860::8888", "8.8.8.8 && true",
	} {
		if _, _, err := Target(target, Fake); err == nil {
			t.Errorf("accepted unsafe target %q", target)
		}
	}
	if _, _, err := Target("198.51.100.23", "arbitrary-lua"); err == nil {
		t.Fatal("accepted arbitrary packet injection preset")
	}
}

func TestVerifyBundleMissingAndModifiedFiles(t *testing.T) {
	base := t.TempDir()
	if err := VerifyBundle(base); err == nil {
		t.Fatal("missing signed WinDivert and native binary unexpectedly accepted")
	}
	for name := range pinned {
		path := filepath.Join(base, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("modified"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyBundle(base); err == nil {
		t.Fatal("tampered Zapret2 executable or scripts accepted")
	}
}

func TestPinnedZapret2Bundle(t *testing.T) {
	dir := os.Getenv("KTEST_ZAPRET_DIR")
	if dir == "" {
		t.Skip("requires checksum-pinned Windows bundle prepared by GitHub Actions")
	}
	if err := VerifyBundle(dir); err != nil {
		t.Fatal(err)
	}
}
