//go:build !windows

package coreprocess

import (
	"os"
	"syscall"
)

// On Unix, Configure places the child in its own process
// group and its cancellation path kills that group.
func confineTrackedProcess(proc *os.Process) (func(), error) {
	return func() { _ = syscall.Kill(-proc.Pid, syscall.SIGKILL) }, nil
}
