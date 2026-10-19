//go:build android

package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/coreprocess"
	"github.com/Nishef1/ktest/internal/xraycfg"
	"golang.org/x/sys/unix"
)

// xrayTunPacketAdapter runs the pinned Xray TUN inbound as the preferred
// packet adapter. Xray forwards every flow to KTest's loopback Go SOCKS engine;
// it does not own route selection or an independent Internet exit.
type boundedProcessLog struct {
	mu    sync.Mutex
	data  []byte
	limit int
}

func (b *boundedProcessLog) Write(p []byte) (int, error) {
	n := len(p)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.limit <= 0 {
		return n, nil
	}
	if len(p) >= b.limit {
		b.data = append(b.data[:0], p[len(p)-b.limit:]...)
		return n, nil
	}
	if overflow := len(b.data) + len(p) - b.limit; overflow > 0 {
		copy(b.data, b.data[overflow:])
		b.data = b.data[:len(b.data)-overflow]
	}
	b.data = append(b.data, p...)
	return n, nil
}

func (b *boundedProcessLog) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(append([]byte(nil), b.data...))
}

// classifyXrayExit keeps useful startup diagnostics without exposing raw
// Xray logs, which can include hostnames and addresses, to the UI.
func classifyXrayExit(err error, logText string) string {
	lower := strings.ToLower(logText)
	switch {
	case strings.Contains(lower, "permission denied") || strings.Contains(lower, "bad file descriptor"):
		return "Xray could not access Android's TUN file descriptor"
	case strings.Contains(lower, "failed to start tun") || strings.Contains(lower, "tun device") && strings.Contains(lower, "failed"):
		return "Xray could not initialize its TUN inbound"
	case strings.Contains(lower, "failed to load config") || strings.Contains(lower, "failed to read config"):
		return "Xray rejected the generated TUN configuration"
	case strings.Contains(lower, "connection refused") || strings.Contains(lower, "failed to connect to 127.0.0.1"):
		return "Xray could not reach KTest's local Go SOCKS listener"
	default:
		if err != nil {
			return fmt.Sprintf("Xray TUN process exited (%v)", err)
		}
		return "Xray TUN process exited unexpectedly"
	}
}

type xrayTunPacketAdapter struct {
	mu         sync.Mutex
	nativeDir  string
	privateDir string
	starting   bool
	running    bool
	cancel     context.CancelFunc
	done       chan struct{}
	tunFile    *os.File
	configPath string
	lastError  string
}

func newXrayTunPacketAdapter(nativeDir, privateDir string) androidXrayTun {
	return &xrayTunPacketAdapter{nativeDir: nativeDir, privateDir: privateDir}
}

func (a *xrayTunPacketAdapter) Start(fd int, socksAddress string) bool {
	a.mu.Lock()
	if a.starting || a.running {
		a.mu.Unlock()
		return false
	}
	needsCleanup := a.done != nil
	a.mu.Unlock()
	if needsCleanup {
		a.Stop()
	}
	a.mu.Lock()
	if a.starting || a.running {
		a.mu.Unlock()
		return false
	}
	a.starting = true
	a.lastError = ""
	a.mu.Unlock()

	fail := func(err error) bool {
		a.mu.Lock()
		a.starting = false
		a.lastError = err.Error()
		a.mu.Unlock()
		return false
	}
	if fd < 0 {
		return fail(errors.New("invalid Android TUN file descriptor"))
	}
	if !filepath.IsAbs(a.nativeDir) || !filepath.IsAbs(a.privateDir) || a.privateDir == string(filepath.Separator) {
		return fail(errors.New("Xray TUN requires absolute APK and app-private directories"))
	}
	host, portText, err := net.SplitHostPort(socksAddress)
	if err != nil || host != "127.0.0.1" {
		return fail(errors.New("Xray TUN accepts only KTest's loopback SOCKS listener"))
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fail(errors.New("invalid local Go SOCKS port"))
	}
	probe, err := net.DialTimeout("tcp4", socksAddress, 700*time.Millisecond)
	if err != nil {
		return fail(fmt.Errorf("local Go SOCKS listener is not ready: %w", err))
	}
	_ = probe.SetDeadline(time.Now().Add(700 * time.Millisecond))
	if _, err := probe.Write([]byte{5, 1, 0}); err != nil {
		_ = probe.Close()
		return fail(fmt.Errorf("local Go SOCKS greeting failed: %w", err))
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(probe, greeting); err != nil {
		_ = probe.Close()
		return fail(fmt.Errorf("local Go SOCKS greeting response failed: %w", err))
	}
	_ = probe.Close()
	if greeting[0] != 5 || greeting[1] != 0 {
		return fail(errors.New("local Go SOCKS listener did not accept unauthenticated SOCKS5"))
	}

	binary, err := xraycfg.AndroidBinary(a.nativeDir, runtime.GOARCH)
	if err != nil {
		return fail(err)
	}
	var plan struct {
		MTU int `json:"mtu"`
	}
	if err := json.Unmarshal([]byte(VpnTunPlan()), &plan); err != nil || plan.MTU < 1280 {
		return fail(errors.New("Go-owned Android TUN plan is invalid"))
	}
	config, err := xraycfg.TunConfig(port, plan.MTU)
	if err != nil {
		return fail(err)
	}
	stateDir := filepath.Join(a.privateDir, "xray-tun")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fail(fmt.Errorf("Xray private state directory: %w", err))
	}
	file, err := os.CreateTemp(stateDir, "tun-*.json")
	if err != nil {
		return fail(fmt.Errorf("Xray TUN config: %w", err))
	}
	configPath := file.Name()
	cleanupConfig := func() {
		_ = file.Close()
		_ = os.Remove(configPath)
	}
	if err := file.Chmod(0600); err != nil {
		cleanupConfig()
		return fail(err)
	}
	if _, err := file.Write(config); err != nil {
		cleanupConfig()
		return fail(err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(configPath)
		return fail(err)
	}

	// ExtraFiles passes a duplicate of Android's TUN fd to the child as fd 3.
	// Never wrap or close the original fd: ParcelFileDescriptor owns it.
	dupFD, err := unix.Dup(fd)
	if err != nil {
		_ = os.Remove(configPath)
		return fail(fmt.Errorf("duplicate Android TUN fd for Xray: %w", err))
	}
	tunFile := os.NewFile(uintptr(dupFD), "ktest-android-tun")
	if tunFile == nil {
		_ = unix.Close(dupFD)
		_ = os.Remove(configPath)
		return fail(errors.New("could not wrap duplicated Android TUN fd"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := coreprocess.Command(ctx, binary, "run", "-c", configPath)
	cmd.Env = withEnvValue(withEnvValue(os.Environ(), "xray.tun.fd", "3"), "XRAY_TUN_FD", "3")
	cmd.ExtraFiles = []*os.File{tunFile}
	startupLog := &boundedProcessLog{limit: 4096}
	cmd.Stdout, cmd.Stderr = io.Discard, startupLog
	done := make(chan struct{})

	a.mu.Lock()
	a.cancel, a.done, a.tunFile, a.configPath = cancel, done, tunFile, configPath
	a.running = true // provisional until the child exits or the startup grace elapses
	a.starting = false
	a.mu.Unlock()

	go func() {
		runErr := coreprocess.Run(cmd)
		_ = tunFile.Close()
		_ = os.Remove(configPath)
		a.mu.Lock()
		a.running = false
		a.starting = false
		if ctx.Err() == nil {
			a.lastError = classifyXrayExit(runErr, startupLog.String())
		}
		a.mu.Unlock()
		close(done)
	}()

	// Xray has no listener to wait on for a TUN inbound. Reject fast config/fd
	// failures, then monitor process liveness and automatically fall back to HEV.
	select {
	case <-done:
		return false
	case <-time.After(1200 * time.Millisecond):
		return a.IsRunning()
	}
}

func (a *xrayTunPacketAdapter) Stop() {
	a.mu.Lock()
	cancel, done := a.cancel, a.done
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	a.mu.Lock()
	if a.done == done {
		a.cancel, a.done, a.tunFile, a.configPath = nil, nil, nil, ""
		a.running, a.starting = false, false
	}
	a.mu.Unlock()
}

func (a *xrayTunPacketAdapter) IsRunning() bool {
	a.mu.Lock()
	running, done := a.running, a.done
	a.mu.Unlock()
	if !running || done == nil {
		return false
	}
	select {
	case <-done:
		return false
	default:
		return true
	}
}

func (*xrayTunPacketAdapter) SupportsUDP() bool  { return true }
func (*xrayTunPacketAdapter) SupportsIPv6() bool { return true }
func (a *xrayTunPacketAdapter) LastError() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastError
}

func withEnvValue(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			out = append(out, item)
		}
	}
	return append(out, prefix+value)
}
