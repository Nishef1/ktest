//go:build windows

package main

import (
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// `go run` ends immediately on Ctrl+C and leaves the program it started
// running in the same console: the shell prompt comes back while ktest still
// owns the keyboard and the alternate screen. When the parent is go.exe and it
// goes away, restore the terminal, stop the cores and exit.
func exitWithGoRun() {
	parent := parentProcess()
	if parent == nil {
		return
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, parent.ProcessID)
	if err != nil {
		return
	}
	go func() {
		_, _ = windows.WaitForSingleObject(h, windows.INFINITE)
		_, _ = os.Stdout.WriteString("\x1b[0m\x1b[?1049l\x1b[?25h")
		reapTracked()
		os.Exit(130)
	}()
}

func parentProcess() *windows.ProcessEntry32 {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	self := uint32(os.Getpid())
	var entries []windows.ProcessEntry32
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		entries = append(entries, e)
	}
	for _, c := range entries {
		if c.ProcessID == self {
			for _, p := range entries {
				if p.ProcessID == c.ParentProcessID && strings.EqualFold(windows.UTF16ToString(p.ExeFile[:]), "go.exe") {
					pp := p
					return &pp
				}
			}
		}
	}
	return nil
}
