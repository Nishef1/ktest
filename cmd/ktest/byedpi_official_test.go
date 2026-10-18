package main

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/byedpi"
)

// The Windows portable workflow invokes this against its checksum-pinned,
// unmodified upstream ciadpi.exe. Regular Go/unit CI skips when no native
// ByeDPI binary is provided. No remote connection or DPI test is performed.
func TestOfficialByeDPIStartsAllBuiltInStrategies(t *testing.T) {
	bin := os.Getenv("KTEST_BYEDPI_BIN")
	if bin == "" {
		t.Skip("requires the official packaged ByeDPI executable")
	}
	list, err := byedpi.ParseStrategies(strings.NewReader(byedpi.DefaultStrategies))
	if err != nil {
		t.Fatal(err)
	}
	for _, strategy := range list {
		t.Run(strategy.Label, func(t *testing.T) {
			probe, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := probe.Addr().String()
			port := strconv.Itoa(probe.Addr().(*net.TCPAddr).Port)
			_ = probe.Close()
			ctx, cancel := context.WithCancel(context.Background())
			args := append([]string{"-i", "127.0.0.1", "-p", port}, strategy.Args...)
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
			if err := cmd.Start(); err != nil {
				cancel()
				t.Fatal(err)
			}
			done := make(chan struct{})
			var runErr error
			go func() {
				runErr = cmd.Wait()
				close(done)
			}()
			checkCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			ready := byedpi.WaitReady(checkCtx, done, address)
			stop()
			cancel()
			<-done
			if !ready {
				t.Fatalf("official ciadpi did not expose SOCKS5 for %q: %v", strategy.Label, runErr)
			}
		})
	}
}
