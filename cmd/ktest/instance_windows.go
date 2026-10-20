//go:build windows

package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

// claimSession takes a per-user named mutex for the life of one connection.
// Two sessions at once fight over the same loopback ports, WARP keys and
// system proxy; the second one is refused instead. Windows releases the mutex
// when the process ends, however it ends.
func claimSession() (release func(), err error) {
	name, err := windows.UTF16PtrFromString(`Local\ktest-connection-session`)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateMutex(nil, true, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if h != 0 {
			windows.CloseHandle(h)
		}
		return nil, errAnotherSession
	}
	if err != nil {
		return func() {}, nil // cannot tell; do not block connecting
	}
	return func() { windows.ReleaseMutex(h); windows.CloseHandle(h) }, nil
}
