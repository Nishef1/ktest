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
	"github.com/Nishef1/ktest/internal/revive"
	"github.com/Nishef1/ktest/internal/smartproxy"
	"github.com/Nishef1/ktest/internal/xraycfg"
)

// launchAndroidServerless runs a pinned upstream v65 configuration behind
// loopback, without system routes or an imported user-controlled profile.
// Its original DNS/fragment/OOB policy belongs to Xray and uses the ISP IP.
func launchAndroidServerless(ctx context.Context, nativeDir, privateDir, variant string) (*localCoreSet, error) {
	binary, err := xraycfg.AndroidBinary(nativeDir, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	assets := filepath.Join(privateDir, "xray-serverless-assets")
	if err := xraycfg.VerifyAndroidServerlessAssets(assets); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	payload, err := revive.SelectPinnedProfileOnPort(variant, port)
	if err != nil {
		return nil, err
	}
	stateDir := filepath.Join(privateDir, "xray-serverless")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("Serverless private configuration: %w", err)
	}
	file, err := os.CreateTemp(stateDir, "profile-*.json")
	if err != nil {
		return nil, err
	}
	path := file.Name()
	if err := file.Chmod(0600); err != nil {
		file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if _, err := file.Write(payload); err != nil {
		file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	core := &nativeCore{address: address, method: "Serverless " + variant, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(core.done)
		defer os.Remove(path)
		cmd := coreprocess.Command(runCtx, binary, "run", "-c", path)
		cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+assets)
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		core.err = coreprocess.Run(cmd)
	}()
	readyCtx, finish := context.WithTimeout(ctx, 8*time.Second)
	ready := byedpi.WaitReady(readyCtx, core.done, address)
	finish()
	if !ready || ctx.Err() != nil {
		core.stop()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("Serverless Xray could not start its local proxy; check packaged geo assets and profile")
	}
	return &localCoreSet{
		cores: []*nativeCore{core},
		upstreams: []smartproxy.Upstream{{
			Name: core.method, Addr: core.address, LocalBypass: true,
			// Xray has its own validated DNS chain; give it the requested name.
			LocalDNS: false,
		}},
	}, nil
}
