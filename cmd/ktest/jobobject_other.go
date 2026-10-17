//go:build !windows

package main

import "os/exec"

func hideConsole(*exec.Cmd) {}

// killChildrenOnExit is Windows-only; on Unix the cores are children of the
// process group and receive the terminal's hangup.
func killChildrenOnExit() {}
