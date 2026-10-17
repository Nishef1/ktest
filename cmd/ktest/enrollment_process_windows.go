//go:build windows

package main

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// Aether can start a Psiphon child for enrollment. Cancelling setup must
// stop that child too, rather than leave it holding a port after Back.
func configureEnrollmentProcess(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		kill := exec.CommandContext(ctx, "taskkill.exe", "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F")
		kill.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
		_ = kill.Run()
		if err := cmd.Process.Kill(); err != nil {
			return os.ErrProcessDone
		}
		return nil
	}
}
