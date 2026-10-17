//go:build !windows

package coreprocess

import "os/exec"

func HideConsole(*exec.Cmd) {}

// KillChildrenOnExit is Windows-only; on Unix the cores are children of the
// process group and receive the terminal's hangup.
func KillChildrenOnExit() {}
