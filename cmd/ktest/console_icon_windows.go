//go:build windows

package main

import (
	"sync"
	"syscall"
	"unsafe"
)

var consoleIconOnce sync.Once

// setConsoleIcon gives the classic console window ktest's own icon and title
// instead of the generic console glyph. Windows Terminal draws its own icon
// for its tabs and ignores this; it is harmless there.
func setConsoleIcon() {
	consoleIconOnce.Do(func() {
		kernel := syscall.NewLazyDLL("kernel32.dll")
		user := syscall.NewLazyDLL("user32.dll")
		hwnd, _, _ := kernel.NewProc("GetConsoleWindow").Call()
		if hwnd == 0 {
			return
		}
		module, _, _ := kernel.NewProc("GetModuleHandleW").Call(0)
		const (
			imageIcon = 1
			wmSetIcon = 0x0080
			iconSmall = 0
			iconBig   = 1
		)
		load := user.NewProc("LoadImageW")
		send := user.NewProc("SendMessageW")
		// Resource 1 is the icon linked in by ktest-icon_windows_amd64.syso.
		for _, s := range []struct{ kind, size uintptr }{{iconBig, 32}, {iconSmall, 16}} {
			if h, _, _ := load.Call(module, 1, imageIcon, s.size, s.size, 0); h != 0 {
				send.Call(hwnd, wmSetIcon, s.kind, h)
			}
		}
		if title, err := syscall.UTF16PtrFromString("ktest"); err == nil {
			kernel.NewProc("SetConsoleTitleW").Call(uintptr(unsafe.Pointer(title)))
		}
	})
}
