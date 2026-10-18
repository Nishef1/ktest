package main

import (
	"context"
	"github.com/Nishef1/ktest/internal/coreprocess"
	"os/exec"
	"time"
)

// The terminal uses the same scoped child-process lifecycle as Android.
func runTracked(cmd *exec.Cmd) error { return coreprocess.Run(cmd) }
func reapTracked() int               { return coreprocess.Reap() }
func trackedCount() int              { return coreprocess.Count() }
func waitTrackedGone(ctx context.Context, limit time.Duration) bool {
	return coreprocess.WaitGone(ctx, limit)
}
func configureEnrollmentProcess(cmd *exec.Cmd) { coreprocess.Configure(cmd) }
func hideConsole(cmd *exec.Cmd)                { coreprocess.HideConsole(cmd) }
func killChildrenOnExit()                      { coreprocess.KillChildrenOnExit() }
