package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPortFreeDetectsForeignListener(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := portFree(port); err == nil {
		t.Fatal("a port that is already listening must not be reported free")
	}
	l.Close()
	if err := portFree(port); err != nil {
		t.Fatalf("released port reported busy: %v", err)
	}
}

func TestWaitForPortOutlastsSlowCoreStartup(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	// A core that opens its listener late (slow preflight, antivirus scan) must
	// still be detected: readiness is polling, not a one-shot deadline.
	go func() {
		time.Sleep(700 * time.Millisecond)
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return
		}
		defer l.Close()
		time.Sleep(2 * time.Second)
	}()
	if !waitForPort(context.Background(), make(chan struct{}), port, 5*time.Second) {
		t.Fatal("late listener was not detected")
	}
}

func TestWaitForPortStopsWhenCoreExits(t *testing.T) {
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	done := make(chan struct{})
	close(done)
	start := time.Now()
	if waitForPort(context.Background(), done, port, 30*time.Second) {
		t.Fatal("nothing listens, must not report ready")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("did not return promptly after the core exited")
	}
}

func TestTailBufferKeepsOnlyRecentOutput(t *testing.T) {
	b := &tailBuffer{max: 16}
	fmt.Fprint(b, "old line that is long\nlast line")
	if got := b.lastLine(); got != "last line" {
		t.Fatalf("lastLine=%q", got)
	}
	if len(b.data) > 16 {
		t.Fatalf("buffer grew to %d", len(b.data))
	}
}

func TestAutoRejectsUnknownMethod(t *testing.T) {
	if code := runAuto([]string{"-methods", "1,9"}); code != 2 {
		t.Fatalf("code=%d", code)
	}
}

func TestAutoWithoutBundleReportsEveryMissingMethod(t *testing.T) {
	// Nothing to launch in an empty folder: every method is skipped, none is
	// claimed to work, and the exit code says so.
	if code := runAuto([]string{"-base", t.TempDir(), "-methods", "1,3"}); code != 1 {
		t.Fatalf("code=%d", code)
	}
}

func TestUsageMentionsNewCommands(t *testing.T) {
	for _, want := range []string{"ktest auto", "ktest doctor"} {
		if !strings.Contains(usageText, want) {
			t.Fatalf("usage lacks %q", want)
		}
	}
}
