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
	"unsafe"
)

// IsAdmin reports whether the process may install the tunnel (fltmc succeeds
// only for an elevated token).
func IsAdmin() bool { return exec.Command("fltmc.exe").Run() == nil }

// PhysicalNetwork finds the real default network interface and the DNS servers
// configured on it. It must run BEFORE the tunnel installs its routes and DNS,
// and it rejects VPN and virtual interfaces rather than guessing through them.
func PhysicalNetwork(ctx context.Context) (nic string, dns []string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	ps := "$n = (Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -notmatch '(tun|tap|wintun|vpn|wireguard|loopback)' } | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 -ExpandProperty InterfaceAlias); " +
		"if ($n) { $n; (Get-DnsClientServerAddress -InterfaceAlias $n -AddressFamily IPv4).ServerAddresses }"
	out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput()
	if err != nil {
		return "", nil, errors.New("cannot safely identify a physical default network interface")
	}
	// Interface aliases may contain spaces, so the first line is taken whole.
	text := strings.Split(strings.ReplaceAll(strings.TrimSpace(string(out)), "\r", ""), "\n")
	if len(text) == 0 || strings.TrimSpace(text[0]) == "" {
		return "", nil, errors.New("cannot safely identify a physical default network interface")
	}
	nic = strings.TrimSpace(text[0])
	for _, l := range text[1:] {
		if l = strings.TrimSpace(l); l != "" {
			dns = append(dns, l)
		}
	}
	return nic, dns, nil
}

// Elevate starts this program again with the given arguments in a new window,
// asking Windows for Administrator rights (the user sees the UAC prompt and
// decides). It returns once the request was handed to Windows.
func Elevate(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir, _ := os.Getwd()
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	shell := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(strings.Join(quoted, " "))
	wd, _ := syscall.UTF16PtrFromString(dir)
	ret, _, callErr := shell.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(params)), uintptr(unsafe.Pointer(wd)), 1)
	if ret <= 32 {
		return fmt.Errorf("Windows did not start the elevated window (%v)", callErr)
	}
	return nil
}

// Start requires an already functioning SOCKS5 proxy. It never silently
// enables Windows route changes, DNS interception, or administrator elevation.
func Start(ctx context.Context, coreDir string, port int, output io.Writer) error {
	if !IsAdmin() {
		return errors.New("TUN requires Administrator; reopen Windows Terminal as Administrator before enabling it")
	}
	nic, _, err := PhysicalNetwork(ctx)
	if err != nil {
		return fmt.Errorf("%w; TUN was not started", err)
	}
	payload, err := BuildConfig(port, nic)
	if err != nil {
		return err
	}
	return launch(ctx, coreDir, payload, nic, "TCP only; DNS over HTTPS via SOCKS", output)
}

// StartSystem runs the system-wide tunnel described by o until ctx ends.
// o.PhysicalNIC must come from PhysicalNetwork.
func StartSystem(ctx context.Context, coreDir string, o Options, output io.Writer) error {
	if !IsAdmin() {
		return errors.New("the system-wide tunnel requires Administrator")
	}
	o.DirectProcessPaths = append(append([]string(nil), o.DirectProcessPaths...), filepath.Join(coreDir, "sing-box.exe"))
	payload, err := BuildSystemConfig(o)
	if err != nil {
		return err
	}
	return launch(ctx, coreDir, payload, o.PhysicalNIC, "TCP only; names are answered locally", output)
}

func launch(ctx context.Context, coreDir string, payload []byte, nic, what string, output io.Writer) error {
	binary := filepath.Join(coreDir, "sing-box.exe")
	driver := filepath.Join(coreDir, "wintun.dll")
	for _, p := range []string{binary, driver} {
		if f, err := os.Stat(p); err != nil || f.IsDir() {
			return fmt.Errorf("missing bundled TUN component %s", p)
		}
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
	fmt.Fprintf(output, "TUN starting through %s (%s). Windows routes change while active.\n", nic, what)
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
