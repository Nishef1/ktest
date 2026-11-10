package mobilebridge

import (
	"runtime/debug"
	"testing"
)

func TestApplyMemoryTuning(t *testing.T) {
	t.Setenv("GOGC", "")
	t.Setenv("GOMEMLIMIT", "")
	oldPercent := debug.SetGCPercent(100)
	oldLimit := debug.SetMemoryLimit(-1)
	defer func() {
		debug.SetGCPercent(oldPercent)
		debug.SetMemoryLimit(oldLimit)
	}()
	applyMemoryTuning()
	if got := debug.SetMemoryLimit(-1); got != androidMemoryByte {
		t.Fatalf("memory limit = %d, want %d", got, androidMemoryByte)
	}
	if got := debug.SetGCPercent(100); got != androidGCPercent {
		t.Fatalf("gc percent = %d, want %d", got, androidGCPercent)
	}
}

func TestTrimMemoryDoesNotPanic(t *testing.T) { TrimMemory() }
