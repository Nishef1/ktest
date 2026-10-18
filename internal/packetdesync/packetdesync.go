// Package packetdesync manages an opt-in, single-target Windows Zapret2 trial.
// Unlike ByeDPI this operates at the packet layer; it is not a SOCKS upstream.
package packetdesync

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/coreprocess"
)

type Strategy string

const (
	Fake  Strategy = "fake"
	Split Strategy = "split"
)

// Source files are pinned to the official zapret-win-bundle Git tree at
// 6eb463a6758fb48cd101bc55dfd057e6e9d98af1, carrying Zapret2 1.0.5.2.
// Check Git object IDs for all files, not only the presence of a DLL/driver.
var pinned = map[string]string{
	"winws2.exe":             "8ffd2def2df7dc3e8b1623fdb9a67a94e916fa21",
	"cygwin1.dll":            "1bb2e05c6d5458ad7987859a17172b635e87b9c5",
	"WinDivert.dll":          "2c55eeb6921351a6cad292a900f4b8d7d41c4bcc",
	"WinDivert64.sys":        "218ccaf423ef0a67696226f9ef3a09149e4441d0",
	"lua/zapret-lib.lua":     "c954afd0718534f2eb49d67f08a291e325f68cb1",
	"lua/zapret-antidpi.lua":"80f372a63774ca10ce85fd7dcd5d1e95c3f5bfb7",
}

func VerifyBundle(dir string) error {
	for name, want := range pinned {
		path := filepath.Join(dir, filepath.FromSlash(name))
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("Zapret2 required file %s: %w", name, err)
		}
		h := sha1.New()
		_, _ = fmt.Fprintf(h, "blob %d\x00", len(data))
		_, _ = h.Write(data)
		if got := hex.EncodeToString(h.Sum(nil)); got != want {
			return fmt.Errorf("Zapret2 %s differs from pinned upstream Git blob", name)
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
	if strategy != Fake && strategy != Split {
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
	}
	return filter, args, nil
}

type Trial struct {
	cancel context.CancelFunc
	done   chan error
}

func Start(ctx context.Context, base, ip string, strategy Strategy, log io.Writer) (*Trial, error) {
	if runtime.GOOS != "windows" {
		return nil, errors.New("Zapret2 packet interception is Windows-only")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	_, args, err := Target(ip, strategy)
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
	trial := &Trial{cancel: cancel, done: make(chan error, 1)}
	go func() {
		trial.done <- coreprocess.Run(cmd)
	}()
	timer := time.NewTimer(1100 * time.Millisecond)
	defer timer.Stop()
	select {
	case err := <-trial.done:
		cancel()
		if err == nil {
			err = errors.New("winws2 stopped before the probe started")
		}
		return nil, fmt.Errorf("Zapret2 failed at startup: %w", err)
	case <-ctx.Done():
		cancel()
		select {
		case <-trial.done:
		case <-time.After(4 * time.Second):
		}
		return nil, ctx.Err()
	case <-timer.C:
		// Stable process existence is necessary, not evidence the driver is
		// intercepting. The paired experiment must measure actual reachability.
		select {
		case err := <-trial.done:
			cancel()
			return nil, fmt.Errorf("Zapret2 exited during startup: %v", err)
		default:
			return trial, nil
		}
	}
}

func (t *Trial) Stop() error {
	if t == nil {
		return nil
	}
	t.cancel()
	timer := time.NewTimer(6 * time.Second)
	defer timer.Stop()
	select {
	case <-t.done:
		return nil // expected cancellation
	case <-timer.C:
		return errors.New("Zapret2 process cleanup not confirmed within 6 seconds")
	}
}

// The contract is intentionally narrow: no arbitrary WinDivert expression,
// ports or injected Lua are accepted from the user.
func Port() string { return strconv.Itoa(443) }
func AvailableStrategies() string { return strings.Join([]string{string(Fake), string(Split)}, ", ") }
