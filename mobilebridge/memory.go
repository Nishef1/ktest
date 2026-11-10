package mobilebridge

import (
	"os"
	"runtime/debug"
)

// Android phones have little RAM and the Go side only relays and probes; the
// packaged cores run as separate processes. A softer GC target plus a soft
// memory limit keeps the heap small without capping it hard: above the limit
// the collector works harder instead of the app being killed, and below it
// nothing changes. Explicit GOGC / GOMEMLIMIT from the environment win.
const (
	androidGCPercent  = 50
	androidMemoryByte = 256 << 20
)

func applyMemoryTuning() {
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(androidGCPercent)
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(androidMemoryByte)
	}
}

// TrimMemory returns unused heap to the OS. Android calls it when the UI is
// hidden or the system reports memory pressure; it forces one collection, so
// the caller throttles it and runs it off the main thread.
func TrimMemory() {
	debug.FreeOSMemory()
}
