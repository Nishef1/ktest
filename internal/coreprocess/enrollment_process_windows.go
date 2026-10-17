//go:build windows

package coreprocess

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// KillTree ends a core and everything it started.
func KillTree(pid int) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	kill := exec.CommandContext(ctx, "taskkill.exe", "/PID", strconv.Itoa(pid), "/T", "/F")
	kill.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	_ = kill.Run()
}

// Aether can start a Psiphon child for enrollment. Cancelling setup must
// stop that child too, rather than leave it holding a port after Back.
func Configure(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		KillTree(cmd.Process.Pid)
		if err := cmd.Process.Kill(); err != nil {
			return os.ErrProcessDone
		}
		return nil
	}
}
