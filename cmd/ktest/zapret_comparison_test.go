package main

import (
	"context"
	"io"
	"runtime"
	"testing"
)

func TestZapretModeOptions(t *testing.T) {
	for _, option := range []string{"off", "fake", "split"} {
		if !zapretOptionValid(option) {
			t.Errorf("official Zapret2 option rejected: %q", option)
		}
	}
	for _, option := range []string{"", "all", "fake,split", "custom", "--wf-raw=all"} {
		if zapretOptionValid(option) {
			t.Errorf("unapproved driver strategy accepted: %q", option)
		}
	}
}

func TestWindscribeZapretRejectsInvalidAndUnsupportedPlatforms(t *testing.T) {
	u := newTerm(io.Discard)
	if rc := runWindscribeTestContext(context.Background(), []string{
		"-target", "Some Location", "-sni", "example.com", "-zapret", "custom",
	}, u); rc != 2 {
		t.Fatalf("invalid Zapret2 mode exited %d, want 2", rc)
	}
	if runtime.GOOS != "windows" {
		if rc := runWindscribeTestContext(context.Background(), []string{
			"-target", "Some Location", "-sni", "example.com", "-transport", "wstunnel",
			"-zapret", "fake",
		}, u); rc != 2 {
			t.Fatalf("non-Windows Zapret2 attempt exited %d, want 2", rc)
		}
	}
}
