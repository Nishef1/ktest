// Package packetdesync manages an opt-in, single-target Windows Zapret2 trial.
// Unlike ByeDPI this operates at the packet layer; it is not a SOCKS upstream.
package packetdesync

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/coreprocess"
)

type Strategy string

const (
	Fake  Strategy = "fake"
	Split Strategy = "split"
	Combo Strategy = "combo"
)

// Source files are pinned to the official zapret-win-bundle Git tree at
// 6eb463a6758fb48cd101bc55dfd057e6e9d98af1, carrying Zapret2 1.0.5.2.
// Pinned SHA-256 digests were obtained from the Git-blob-verified Windows
// artifact in CI. Verify at runtime too, not merely file presence.
var pinned = map[string]string{
	"winws2.exe":             "eb9807972c15f05a00416b0549d766a71c9186f8101d406e3cc6c16278164d9e",
	"cygwin1.dll":            "103104a52e5293ce418944725df19e2bf81ad9269b9a120d71d39028e821499b",
	"WinDivert.dll":          "16abd6a029e65557c6a309bea7b13bf81fff4e193567582e1cddbf6719f323e0",
	"WinDivert64.sys":        "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2",
	"lua/zapret-lib.lua":     "cb21ddedd08fa78f87c091de33bdd7e5c0bd24adfff4868078f77197c5992137",
	"lua/zapret-antidpi.lua": "31c9dd75b0bd55e98e5306293f2be81e9d2ecadcbbf9157394ff37dcff7dc85a",
}

func VerifyBundle(dir string) error {
	for name, want := range pinned {
		path := filepath.Join(dir, filepath.FromSlash(name))
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("Zapret2 required file %s: %w", name, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
			return fmt.Errorf("Zapret2 %s SHA-256 differs from the pinned official bundle", name)
		}
	}
	return nil
}

func Target(ip string, strategy Strategy) (string, []string, error) {
	addr := net.ParseIP(ip)
	if addr == nil || addr.To4() == nil || !addr.IsGlobalUnicast() ||
		addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return "", nil, errors.New("Zapret2 requires an exact public IPv4 Windscribe entry")
	}
	if strategy != Fake && strategy != Split && strategy != Combo {
		return "", nil, fmt.Errorf("unsupported Zapret2 strategy %q", strategy)
	}
	ip = addr.To4().String()
	// NETWORK packets do not expose a process ID. Only packets in this exact
	// remote TCP flow are captured (still not process-private).
	filter := fmt.Sprintf("ip and tcp and !loopback and !impostor and ((outbound and ip.DstAddr == %s and tcp.DstPort == 443) or (inbound and ip.SrcAddr == %s and tcp.SrcPort == 443))", ip, ip)
	args := []string{
		"--wf-raw=" + filter,
		"--debug=1",
		"--lua-init=@lua/zapret-lib.lua",
		"--lua-init=@lua/zapret-antidpi.lua",
		"--filter-tcp=443",
		"--filter-l7=tls",
		"--payload=tls_client_hello",
	}
	switch strategy {
	case Fake:
		args = append(args, "--lua-desync=fake:blob=fake_default_tls:tcp_md5:tls_mod=rnd,rndsni,dupsid")
	case Split:
		args = append(args, "--lua-desync=multisplit:pos=1,midsld")
	case Combo:
		// Upstream Zapret2 uses ordered Lua instances: a fake TLS packet
		// followed by a sequence-overlapped split of the real ClientHello.
		args = append(args,
			"--lua-desync=fake:blob=fake_default_tls:tcp_md5:tls_mod=rnd,rndsni,dupsid",
			"--lua-desync=multisplit:pos=1,midsld:seqovl=5:seqovl_pattern=0x1603030000",
		)
	}
	return filter, args, nil
}

// FlowTarget limits interception to one already owned TCP socket. The socket
// stays open until the filter is removed, so another process cannot acquire
// the same local port / remote address tuple during the trial.
func FlowTarget(ip string, localPort int, strategy Strategy) (string, []string, error) {
	filter, args, err := Target(ip, strategy)
	if err != nil {
		return "", nil, err
	}
	if localPort < 1 || localPort > 65535 {
		return "", nil, errors.New("Zapret2 requires an owned local TCP port")
	}
	filter = strings.ReplaceAll(filter, "tcp.DstPort == 443)", fmt.Sprintf("tcp.DstPort == 443 and tcp.SrcPort == %d)", localPort))
	filter = strings.ReplaceAll(filter, "tcp.SrcPort == 443)", fmt.Sprintf("tcp.SrcPort == 443 and tcp.DstPort == %d)", localPort))
	args[0] = "--wf-raw=" + filter
	return filter, args, nil
}

type Trial struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan error
}

// ErrCleanupUnconfirmed means the owned process has not been observed exiting.
// A caller may retry a canceled attempt only when cleanup was confirmed.
var ErrCleanupUnconfirmed = errors.New("Zapret2 process cleanup unconfirmed")

func Start(ctx context.Context, base, ip string, strategy Strategy, log io.Writer) (*Trial, error) {
	return start(ctx, base, ip, 0, strategy, log)
}

func start(ctx context.Context, base, ip string, localPort int, strategy Strategy, log io.Writer) (*Trial, error) {
	if runtime.GOOS != "windows" {
		return nil, errors.New("Zapret2 packet interception is Windows-only")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	_, args, err := Target(ip, strategy)
	if localPort != 0 {
		_, args, err = FlowTarget(ip, localPort, strategy)
	}
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(base, "cores", "zapret2")
	if err := VerifyBundle(dir); err != nil {
		return nil, err
	}
	if log == nil {
		log = io.Discard
	}
	runCtx, cancel := context.WithCancel(ctx)
	cmd := coreprocess.Command(runCtx, filepath.Join(dir, "winws2.exe"), args...)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = log, log
	trial := &Trial{ctx: runCtx, cancel: cancel, done: make(chan error, 1)}
	go func() {
		trial.done <- coreprocess.Run(cmd)
	}()
	if err := trial.awaitStartup(ctx); err != nil {
		return nil, err
	}
	return trial, nil
}

func (t *Trial) awaitStartup(ctx context.Context) error {
	timer := time.NewTimer(1100 * time.Millisecond)
	defer timer.Stop()
	select {
	case err := <-t.done:
		t.cancel()
		if ctx.Err() != nil {
			return ctx.Err() // process exit is already confirmed
		}
		if err == nil {
			err = errors.New("winws2 stopped before the probe started")
		}
		return fmt.Errorf("Zapret2 failed at startup: %w", err)
	case <-ctx.Done():
		return errors.Join(ctx.Err(), t.stopAndWait(4*time.Second))
	case <-timer.C:
		// Stable process existence is necessary, not evidence the driver is
		// intercepting. The paired experiment must measure actual reachability.
		select {
		case err := <-t.done:
			t.cancel()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("Zapret2 exited during startup: %v", err)
		default:
			return nil
		}
	}
}

func (t *Trial) Stop() error {
	if t == nil {
		return nil
	}
	// A driver error after the startup settle must not be counted as a
	// packet-shaped trial merely because the outbound probe continued.
	select {
	case err := <-t.done:
		interrupted := t.ctx != nil && t.ctx.Err() != nil
		t.cancel()
		if interrupted {
			return nil // canceled and reaped, so another attempt may safely start
		}
		return fmt.Errorf("Zapret2 stopped before trial cleanup: %v", err)
	default:
	}
	return t.stopAndWait(6 * time.Second)
}

func (t *Trial) stopAndWait(timeout time.Duration) error {
	t.cancel()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-t.done:
		return nil // expected cancellation
	case <-timer.C:
		return fmt.Errorf("%w within %s", ErrCleanupUnconfirmed, timeout)
	}
}
