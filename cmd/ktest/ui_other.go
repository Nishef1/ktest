//go:build !windows

package main

import "os"

// enableVT reports whether f is an interactive terminal; Unix terminals
// already process escape sequences.
func enableVT(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
