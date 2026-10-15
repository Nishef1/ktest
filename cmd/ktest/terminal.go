package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/quickcheck"
	"github.com/Nishef1/ktest/internal/revive"
	"github.com/Nishef1/ktest/internal/systemtun"
)

type cliSession struct {
	choice string
	name   string
	port   int
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

type tunSession struct {
	cancel context.CancelFunc
	done   chan struct{}
}

type terminal struct {
	out     io.Writer
	mu      sync.Mutex
	active  *cliSession
	tun     *tunSession
	status  string
	results []quickcheck.Result
}

func (t *terminal) print(format string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, _ = fmt.Fprintf(t.out, format, args...)
}

func (t *terminal) current() *cliSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.active
}

func (t *terminal) setStatus(s *cliSession, status string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active == s {
		t.status = status
	}
}

func (t *terminal) stop() bool {
	if !t.stopTunIfActive() {
		return false
	}
	t.mu.Lock()
	s := t.active
	t.mu.Unlock()
	if s == nil {
		t.print("\nNo active mode to stop.\n")
		return true
	}
	t.print("\nStopping %s...\n", s.name)
	s.cancel()
	select {
	case <-s.done:
		t.mu.Lock()
		if t.active == s {
			t.active = nil
			t.status = "stopped"
		}
		t.mu.Unlock()
		t.print("Stopped. You can select another mode.\n")
		return true
	case <-time.After(5 * time.Second):
		t.print("Could not confirm shutdown; refusing to start another core.\n")
		return false
	}
}

func terminalMode(choice string, base string, output io.Writer) (func(context.Context) error, int, string, error) {
	core := filepath.Join(base, "cores")
	profile := filepath.Join(base, "profiles", "Serverless-for-Iran.json")
	if choice == "1" || choice == "2" {
		bin := filepath.Join(core, "xray")
		if runtime.GOOS == "windows" {
			bin += ".exe"
		}
		for _, file := range []string{bin, profile} {
			if info, err := os.Stat(file); err != nil || info.IsDir() {
				return nil, 0, "", fmt.Errorf("missing %s; download and extract the full portable ZIP", file)
			}
		}
		variant := "B"
		if choice == "2" {
			variant = "A"
		}
		return func(ctx context.Context) error {
			return revive.Run(ctx, revive.Config{
				XrayBinary: bin,
				Profile:    profile,
				Variant:    variant,
				AssetDir:   core,
				Output:     output,
			})
		}, 10808, "Xray Fragment " + variant, nil
	}
	if choice == "3" || choice == "4" {
		bin := filepath.Join(core, "ciadpi")
		if runtime.GOOS == "windows" {
			bin += ".exe"
		}
		if info, err := os.Stat(bin); err != nil || info.IsDir() {
			return nil, 0, "", fmt.Errorf("missing %s; download the complete portable ZIP", bin)
		}
		args := []string{"-i", "127.0.0.1", "-p", "10809"}
		label := "ByeDPI TLS record slicing"
		if choice == "3" {
			args = append(args, "--auto=torst", "--timeout", "3", "--tlsrec", "3+s")
			label = "ByeDPI adaptive"
		} else {
			args = append(args, "--tlsrec", "3+s")
		}
		return func(ctx context.Context) error {
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.Stdout, cmd.Stderr = output, output
			err := cmd.Run()
			if ctx.Err() != nil {
				return nil
			}
			if err != nil {
				return fmt.Errorf("ByeDPI exited: %w", err)
			}
			return fmt.Errorf("ByeDPI exited unexpectedly")
		}, 10809, label, nil
	}
	return nil, 0, "", fmt.Errorf("unknown option %q", choice)
}

func (t *terminal) start(choice, base string) {
	if t.current() != nil && !t.stop() {
		return
	}
	launch, port, label, err := terminalMode(choice, base, t.out)
	if err != nil {
		t.print("Cannot start: %v\n", err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &cliSession{
		choice: choice, name: label, port: port, ctx: ctx, cancel: cancel, done: make(chan struct{}),
	}
	t.mu.Lock()
	t.active, t.status, t.results = s, "starting local core", nil
	t.mu.Unlock()
	t.print("\nStarting %s...\n", label)
	go func() {
		err := launch(ctx)
		close(s.done)
		if ctx.Err() != nil {
			return
		}
		t.mu.Lock()
		if t.active == s {
			t.status = fmt.Sprintf("core stopped: %v", err)
			t.active = nil
		}
		t.mu.Unlock()
		t.print("\nCore stopped: %v\n", err)
	}()
	go t.waitAndCheck(ctx, s)
}

func (t *terminal) waitAndCheck(ctx context.Context, s *cliSession) {
	deadline := time.NewTimer(7 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(120 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-deadline.C:
			t.setStatus(s, "proxy did not open in 7 seconds; check core errors")
			t.print("\n%s: proxy did not open at 127.0.0.1:%d.\n", s.name, s.port)
			return
		case <-tick.C:
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", s.port), 200*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				t.setStatus(s, "local proxy listening; checking real websites")
				t.print("\nProxy listening at 127.0.0.1:%d. Verifying YouTube and Google via SOCKS...\n", s.port)
				t.check(ctx, s)
				return
			}
		}
	}
}

func (t *terminal) check(ctx context.Context, s *cliSession) {
	checkCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	results := quickcheck.Run(checkCtx, s.port, 8*time.Second)
	if ctx.Err() != nil || t.current() != s {
		return
	}
	success := 0
	for _, r := range results {
		if r.Success {
			success++
			t.print("PASS %-8s expected HTTP 204 over verified TLS\n", r.Target)
		} else {
			t.print("FAIL %-8s %s\n", r.Target, r.Detail)
		}
	}
	t.mu.Lock()
	if t.active == s {
		t.results = results
		t.status = fmt.Sprintf("%d/%d target websites verified through local SOCKS proxy", success, len(results))
	}
	t.mu.Unlock()
	if success == 0 {
		t.print("No working web connection confirmed. Try a different mode; an open local proxy is not enough.\n")
	} else {
		t.print("At least one website was reached via the selected mode. Public IP and other apps are not verified.\n")
	}
}

// runInteractive replaces the old blocking terminal menu with managed sessions.
// It deliberately keeps Windows routing/DNS unchanged.
func runInteractive(in io.Reader, out io.Writer, base string) int {
	t := &terminal{out: out, status: "disconnected"}
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	quitSignal := make(chan struct{})
	defer close(quitSignal)
	go func() {
		for {
			select {
			case <-quitSignal:
				return
			case <-interrupts:
				t.print("\nCtrl+C: stopping active connection; menu remains available.\n")
				t.stop()
			}
		}
	}()
	reader := bufio.NewScanner(in)
	for {
		t.mu.Lock()
		status := t.status
		t.mu.Unlock()
		t.print("\nktest | Status: %s\n", status)
		t.print("1) Direct Fragment B      2) Direct Fragment A\n")
		t.print("3) ByeDPI adaptive        4) TLS record slicing\n")
		t.print("5) CDN IP candidates      6) Toggle system-wide TUN (Windows/Admin)\n")
		t.print("7) Stop active mode       8) Retest YouTube and Google\n")
		t.print("0) Exit (stops core)\n")
		t.print("Select > ")
		if !reader.Scan() {
			t.stopIfActive()
			return 0
		}
		option := strings.TrimSpace(reader.Text())
		switch option {
		case "1", "2", "3", "4":
			t.start(option, base)
		case "5":
			t.print("CDN candidates are diagnostics only, not working VPN endpoints.\n")
			runQuickScan([]string{"-provider", "akamai"})
		case "6":
			t.mu.Lock()
			exists := t.tun != nil
			t.mu.Unlock()
			if exists {
				t.stopTunIfActive()
				continue
			}
			active := t.current()
			if active == nil {
				t.print("Start and verify a local mode (1-4) first.\n")
				continue
			}
			t.mu.Lock()
			verified := false
			for _, result := range t.results {
				if result.Success {
					verified = true
				}
			}
			t.mu.Unlock()
			if !verified {
				t.print("No verified HTTPS result through proxy. Refusing to change system routes.\n")
				continue
			}
			t.print("BETA: TCP-wide TUN, administrator required; UDP except DNS is blocked.\n")
			t.print("May disrupt Windows/other VPNs. Routes should restore when stopped.\n")
			t.print("Type YES to modify system-wide routes > ")
			if !reader.Scan() {
				t.stopIfActive()
				return 0
			}
			if strings.TrimSpace(reader.Text()) != "YES" {
				t.print("Cancelled.\n")
				continue
			}
			t.startTun(base, active.port)
		case "7", "s", "S":
			t.stop()
		case "8", "t", "T":
			s := t.current()
			if s == nil {
				t.print("No active connection; select mode 1-4 first.\n")
			} else {
				go t.check(s.ctx, s)
			}
		case "0", "q", "Q":
			t.stopIfActive()
			return 0
		default:
			t.print("Unknown option. Select 1-8 or 0 to exit.\n")
		}
	}
}

func (t *terminal) stopIfActive() {
	if t.current() != nil {
		t.stop()
	} else {
		t.stopTunIfActive()
	}
}

func (t *terminal) stopTunIfActive() bool {
	t.mu.Lock()
	ts := t.tun
	t.mu.Unlock()
	if ts == nil {
		return true
	}
	t.print("Stopping Windows TUN and restoring routes...\n")
	ts.cancel()
	select {
	case <-ts.done:
		t.mu.Lock()
		if t.tun == ts {
			t.tun = nil
		}
		t.mu.Unlock()
		t.print("TUN process stopped. Windows should restore its routes.\n")
		return true
	case <-time.After(12 * time.Second):
		t.print("Could not verify TUN shutdown. Do not switch proxy cores until routes recover.\n")
		return false
	}
}

func (t *terminal) startTun(base string, socksPort int) {
	ctx, cancel := context.WithCancel(context.Background())
	ts := &tunSession{cancel: cancel, done: make(chan struct{})}
	t.mu.Lock()
	t.tun = ts
	t.mu.Unlock()
	coreDir := filepath.Join(base, "cores")
	go func() {
		err := systemtun.Start(ctx, coreDir, socksPort, t.out)
		close(ts.done)
		t.mu.Lock()
		if t.tun == ts {
			t.tun = nil
		}
		t.mu.Unlock()
		if ctx.Err() == nil {
			t.print("TUN exited: %v\n", err)
		}
	}()
	// Verify actual system-routed HTTPS and automatically revert on total
	// failure, rather than leaving the user's Windows network stranded.
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-ts.done:
			return
		case <-time.After(3 * time.Second):
		}
		testCtx, stop := context.WithTimeout(ctx, 17*time.Second)
		defer stop()
		results := quickcheck.RunDirect(testCtx, 7*time.Second)
		if ctx.Err() != nil {
			return
		}
		pass := 0
		for _, r := range results {
			if r.Success {
				pass++
			}
		}
		if pass == 0 {
			t.print("TUN direct-route verification failed on both sites; stopping TUN automatically.\n")
			ts.cancel()
		} else {
			t.print("TUN system-route verification: %d/%d sites passed. UDP remains restricted.\n", pass, len(results))
		}
	}()
}
