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
	"strings"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/byedpi"
	"github.com/Nishef1/ktest/internal/coreprocess"
	"github.com/Nishef1/ktest/internal/revive"
	"github.com/Nishef1/ktest/internal/smartproxy"
	"github.com/Nishef1/ktest/internal/xraycfg"
)

// serverlessErrorTail bounds native stderr and redacts local app directories.
// It deliberately does not retain stdout, DNS queries or traffic payloads.
type serverlessErrorTail struct {
	mu sync.Mutex
	data []byte
}

func (w *serverlessErrorTail) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.data = append(w.data, p...)
	if len(w.data) > 2048 {
		w.data = append([]byte(nil), w.data[len(w.data)-2048:]...)
	}
	return len(p), nil
}

func (w *serverlessErrorTail) summary(nativeDir, privateDir string) string {
	w.mu.Lock()
	message := string(w.data)
	w.mu.Unlock()
	message = strings.ReplaceAll(message, privateDir, "[app-private]")
	message = strings.ReplaceAll(message, nativeDir, "[apk-native]")
	message = strings.Join(strings.Fields(message), " ")
	if len(message) > 320 {
		message = message[len(message)-320:]
	}
	return message
}

// A listening TCP socket is not enough: confirm the Xray mixed inbound
// actually speaks SOCKS5 before declaring local proxy readiness.
func serverlessSOCKSReady(ctx context.Context, address string) bool {
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", address)
	if err != nil {
		return false
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return false
	}
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return false
	}
	var reply [2]byte
	return io.ReadFull(conn, reply[:]) == nil && reply == [2]byte{5, 0}
}


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
		stderr := &serverlessErrorTail{}
		cmd := coreprocess.Command(runCtx, binary, "run", "-c", path)
		cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+assets)
		cmd.Stdout, cmd.Stderr = io.Discard, stderr
		runErr := coreprocess.Run(cmd)
		if runErr != nil && runCtx.Err() == nil {
			if detail := stderr.summary(nativeDir, privateDir); detail != "" {
				core.err = fmt.Errorf("Serverless Xray: %w (%s)", runErr, detail)
			} else {
				core.err = fmt.Errorf("Serverless Xray: %w", runErr)
			}
		} else {
			core.err = runErr
		}
	}()
	readyCtx, finish := context.WithTimeout(ctx, 8*time.Second)
	ready := byedpi.WaitReady(readyCtx, core.done, address)
	if ready {
		ready = serverlessSOCKSReady(readyCtx, address)
	}
	finish()
	if !ready || ctx.Err() != nil {
		var failure error
		select {
		case <-core.done:
			failure = core.err
		default:
		}
		core.stop()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if failure != nil {
			return nil, failure
		}
		return nil, errors.New("Serverless Xray did not complete a local SOCKS5 handshake; verify the pinned native core and profile")
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
