package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/Nishef1/ktest/internal/systemtun"
)

// autoElevate reopens the interactive commands (the menu and connect) with
// Administrator rights on Windows, in Windows Terminal when it is installed,
// so nobody has to start an elevated terminal by hand. It reports true once
// the elevated window was started and this process should simply exit.
//
// It never blocks the program: a declined UAC prompt, a missing shell or a
// `go run` build all leave the current process running unelevated as before.
// Set KTEST_NO_ELEVATE=1 to turn it off.
func autoElevate(args []string) bool {
	if runtime.GOOS != "windows" || os.Getenv("KTEST_NO_ELEVATE") != "" {
		return false
	}
	if len(args) > 0 && args[0] != "connect" {
		return false
	}
	if len(args) > 0 && len(args) > 1 && args[1] == elevatedSessionArg {
		return false
	}
	if exe, err := os.Executable(); err != nil || strings.Contains(strings.ToLower(exe), "go-build") {
		// `go run` deletes its temporary executable when the parent exits.
		return false
	}
	if systemtun.IsAdmin() {
		return false
	}
	fmt.Println("ktest needs Administrator for the system tunnel and packet tools. Windows will ask for permission.")
	if err := systemtun.Elevate(args); err != nil {
		fmt.Println("Continuing without Administrator:", err)
		return false
	}
	fmt.Println("Opened in the Administrator window. This one can be closed.")
	return true
}
