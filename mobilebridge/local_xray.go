package mobilebridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Nishef1/ktest/internal/byedpi"
	"github.com/Nishef1/ktest/internal/coreprocess"
	"github.com/Nishef1/ktest/internal/smartproxy"
	"github.com/Nishef1/ktest/internal/xraycfg"
)

// attachAndroidXray adds ONE official, local-only Xray TLS-fragmentation path.
// HEV/Android VpnService remain the sole packet TUN; Go still decides DNS,
// trusted CA fronting, route racing, foreign exits and UDP leak prevention.
// A failing optional Xray core must not disable already working ByeDPI paths.
func attachAndroidXray(ctx context.Context, set *localCoreSet, nativeDir, privateDir string) error {
	if set == nil || !filepath.IsAbs(privateDir) || privateDir == string(filepath.Separator) {
		return errors.New("Xray needs a real absolute Android private directory")
	}
	bin, err := xraycfg.AndroidBinary(nativeDir, runtime.GOARCH)
	if err != nil {
		return err
	}
	stateDir := filepath.Join(privateDir, "xray")
	if err = os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("Xray private configuration: %w", err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	payload, err := xraycfg.ClientConfig(port)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(stateDir, "fragment-*.json")
	if err != nil {
		return err
	}
	configPath := file.Name()
	if err := file.Chmod(0600); err != nil {
		file.Close()
		_ = os.Remove(configPath)
		return err
	}
	if _, err := file.Write(payload); err != nil {
		file.Close()
		_ = os.Remove(configPath)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(configPath)
		return err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	core := &nativeCore{address: address, method: "Xray TLS fragment", cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(core.done)
		defer os.Remove(configPath)
		cmd := coreprocess.Command(runCtx, bin, "run", "-c", configPath)
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		core.err = coreprocess.Run(cmd)
	}()
	readyCtx, finish := context.WithTimeout(ctx, 5*time.Second)
	ok := byedpi.WaitReady(readyCtx, core.done, address)
	finish()
	if !ok || ctx.Err() != nil {
		core.stop()
		return errors.New("official Xray did not provide a working local SOCKS endpoint")
	}
	set.cores = append(set.cores, core)
	set.upstreams = append(set.upstreams, smartproxy.Upstream{
		Name: core.method, Addr: core.address,
		// Go's trusted resolver provides IPs; Xray must not use a poisoned
		// Android system DNS resolver to locate filtered destinations.
		LocalDNS: true, LocalBypass: true, Rank: 3,
	})
	return nil
}
