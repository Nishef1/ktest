//go:build windows

package systemtun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Start requires an already functioning SOCKS5 proxy. It never silently
// enables Windows route changes, DNS interception, or administrator elevation.
func Start(ctx context.Context, coreDir string, port int, output io.Writer) error {
	binary := filepath.Join(coreDir, "sing-box.exe")
	driver := filepath.Join(coreDir, "wintun.dll")
	for _, p := range []string{binary, driver} {
		if f, err := os.Stat(p); err != nil || f.IsDir() {
			return fmt.Errorf("missing bundled TUN component %s", p)
		}
	}
	if err := exec.Command("fltmc.exe").Run(); err != nil {
		return errors.New("TUN requires Administrator; reopen Windows Terminal as Administrator before enabling it")
	}
	discoverCtx, cancelDiscover := context.WithTimeout(ctx, 4*time.Second)
	defer cancelDiscover()
	// Resolve the physical NIC BEFORE installing TUN routes. Reject VPN and
	// virtual interfaces rather than guessing through them.
	ps := "(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -notmatch '(tun|tap|wintun|vpn|wireguard|loopback)' } | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 -ExpandProperty InterfaceAlias)"
	found, err := exec.CommandContext(discoverCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput()
	if err != nil || strings.TrimSpace(string(found)) == "" {
		return errors.New("cannot safely identify a physical default network interface; TUN was not started")
	}
	nic := strings.TrimSpace(string(found))
	payload, err := BuildConfig(port, nic)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp("", "ktest-tun-*.json")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
	if err = file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err = file.Write(payload); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	checkCtx, stopCheck := context.WithTimeout(ctx, 7*time.Second)
	defer stopCheck()
	check := exec.CommandContext(checkCtx, binary, "check", "-c", path)
	check.Dir = coreDir
	result, err := check.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box rejected the TUN config: %w: %s", err, strings.TrimSpace(string(result)))
	}
	fmt.Fprintf(output, "TUN starting through %s (TCP only; DNS over HTTPS via SOCKS). Windows routes change while active.\n", nic)
	cmd := exec.Command(binary, "run", "-c", path)
	cmd.Dir = coreDir
	cmd.Stdout, cmd.Stderr = output, output
	// New Windows console process group supports targeted CTRL_BREAK_EVENT.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000200}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start TUN: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("TUN exited: %v", err)
	case <-ctx.Done():
		// Graceful CTRL_BREAK lets sing-box teardown adapter/routes.
		ctrlBreak := syscall.NewLazyDLL("kernel32.dll").NewProc("GenerateConsoleCtrlEvent")
		ok, _, _ := ctrlBreak.Call(1, uintptr(cmd.Process.Pid))
		if ok == 0 {
			fmt.Fprintln(output, "Warning: Windows did not deliver graceful TUN stop signal.")
		}
		select {
		case <-done:
			return nil
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			fmt.Fprintln(output, "TUN forcibly stopped. If networking fails, disable/re-enable the adapter or reboot to restore routes.")
			return nil
		}
	}
}
