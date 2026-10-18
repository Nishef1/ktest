package mobilebridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/byedpi"
	"github.com/Nishef1/ktest/internal/coreprocess"
	"github.com/Nishef1/ktest/internal/smartproxy"
)

type localCoreSet struct {
	cores     []*nativeCore
	upstreams []smartproxy.Upstream
}

// StartAndroidProxy adds the same native ByeDPI strategies used on desktop.
// The Go policy still owns DNS, route racing and protected foreign-only sites.
func StartAndroidProxy(mode, upstream, nativeLibraryDir string) (string, error) {
	if mode != "balanced" && mode != "fast" {
		return "", errors.New("local bypass cores require Balanced or Fast mode")
	}
	if nativeLibraryDir == "" {
		return "", errors.New("packaged ByeDPI directory is required")
	}
	return startProxy(mode, upstream, nil, nativeLibraryDir)
}

func launchAndroidLocalCores(ctx context.Context, nativeDir string) (*localCoreSet, error) {
	bin, err := byedpi.AndroidBinary(nativeDir, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	strategies, err := byedpi.ParseStrategies(strings.NewReader(byedpi.DefaultStrategies))
	if err != nil {
		return nil, err
	}
	return startLocalCores(ctx, bin, strategies)
}

func startLocalCores(ctx context.Context, bin string, strategies []byedpi.Strategy) (set *localCoreSet, err error) {
	set = &localCoreSet{}
	defer func() {
		if err != nil {
			set.stop()
		}
	}()
	for _, strategy := range strategies {
		if err = ctx.Err(); err != nil {
			return set, err
		}
		l, listenErr := net.Listen("tcp4", "127.0.0.1:0")
		if listenErr != nil {
			return set, listenErr
		}
		address := l.Addr().String()
		port := fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
		_ = l.Close()
		runCtx, cancel := context.WithCancel(context.Background())
		core := &nativeCore{address: address, method: "ByeDPI " + strategy.Label, cancel: cancel, done: make(chan struct{})}
		args := append([]string{"-i", "127.0.0.1", "-p", port}, strategy.Args...)
		set.cores = append(set.cores, core)
		go func() {
			cmd := coreprocess.Command(runCtx, bin, args...)
			cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
			core.err = coreprocess.Run(cmd)
			close(core.done)
		}()
	}
	// Probe all listeners concurrently under one bounded deadline. A slow or
	// hung first process must not prevent a healthy later strategy from joining.
	readyCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ready := make([]bool, len(set.cores))
	var wg sync.WaitGroup
	for i, core := range set.cores {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready[i] = byedpi.WaitReady(readyCtx, core.done, core.address)
		}()
	}
	wg.Wait()
	for i, core := range set.cores {
		if ready[i] {
			set.upstreams = append(set.upstreams, smartproxy.Upstream{
				Name: core.method, Addr: core.address, LocalDNS: true, LocalBypass: true, Rank: 2,
			})
		}
	}
	if err = ctx.Err(); err != nil {
		return set, err
	}
	if len(set.upstreams) == 0 {
		return set, errors.New("packaged ByeDPI did not start a SOCKS5 listener")
	}
	return set, nil
}

func (set *localCoreSet) stop() {
	for _, core := range set.cores {
		core.cancel()
	}
	for _, core := range set.cores {
		<-core.done
	}
}
