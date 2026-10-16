//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// enableVT turns on ANSI escape processing and UTF-8 output for an interactive
// console and reports whether f is one. Windows Terminal and PowerShell 7
// already allow it; the legacy console host needs the flag.
func enableVT(f *os.File) bool {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	getMode := kernel.NewProc("GetConsoleMode")
	setMode := kernel.NewProc("SetConsoleMode")
	var mode uint32
	if r, _, _ := getMode.Call(f.Fd(), uintptr(unsafe.Pointer(&mode))); r == 0 {
		return false // not a console: a pipe or a file
	}
	const enableVirtualTerminalProcessing = 0x0004
	if mode&enableVirtualTerminalProcessing == 0 {
		if r, _, _ := setMode.Call(f.Fd(), uintptr(mode|enableVirtualTerminalProcessing)); r == 0 {
			return false
		}
	}
	kernel.NewProc("SetConsoleOutputCP").Call(65001)
	return true
}
