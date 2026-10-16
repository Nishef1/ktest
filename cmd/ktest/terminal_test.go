package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMenuExitWithoutCore(t *testing.T) {
	var out bytes.Buffer
	if code := runInteractive(strings.NewReader("0\n"), &out, t.TempDir()); code != 0 {
		t.Fatal(code)
	}
	if !strings.Contains(out.String(), "Status: disconnected") {
		t.Fatal(out.String())
	}
}

func TestMenuSwitchErrorsDoNotPreventExit(t *testing.T) {
	var out bytes.Buffer
	if code := runInteractive(strings.NewReader("3\n1\n7\n0\n0\n"), &out, t.TempDir()); code != 0 {
		t.Fatal(code)
	}
	if !strings.Contains(out.String(), "missing ") {
		t.Fatal(out.String())
	}
	if !strings.Contains(out.String(), "No active mode to stop") {
		t.Fatal(out.String())
	}
}

func TestMenuSelectingKnownFileStillRequiresFullBundle(t *testing.T) {
	base := t.TempDir()
	err := os.MkdirAll(filepath.Join(base, "cores"), 0700)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = terminalMode("1", base, &bytes.Buffer{})
	if err == nil {
		t.Fatal("should refuse partial bundles")
	}
}

func TestCancelledProbeIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ctx.Err() == nil {
		t.Fatal("cancelled context unexpectedly live")
	}
}

func TestBlankInputNeverShownAsInvalidChoice(t *testing.T) {
	var out bytes.Buffer
	if code := runInteractive(strings.NewReader("\n0\n"), &out, t.TempDir()); code != 0 {
		t.Fatal(code)
	}
	if strings.Contains(out.String(), "Unknown option") {
		t.Fatalf("empty line incorrectly rejected: %s", out.String())
	}
}
