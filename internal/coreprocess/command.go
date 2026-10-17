// Package coreprocess manages only native cores owned by this KTest process.
// It never searches for or terminates a process by executable name.
package coreprocess

import (
	"context"
	"os/exec"
	"time"
)

// Command starts no shell and confines cancellation to this core's descendants.
// Run must be used to register and reap the resulting command.
func Command(ctx context.Context, binary string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, binary, args...)
	Configure(cmd)
	HideConsole(cmd)
	cmd.WaitDelay = 3 * time.Second
	return cmd
}
