package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPlainTermHasNoEscapeSequencesOrUnicodeDecoration(t *testing.T) {
	var out bytes.Buffer
	u := plainTerm(&out)
	u.Heading("connect", "subtitle")
	u.Line(toneOK, "ready")
	u.Line(toneFail, "failed")
	u.Box("READY", toneOK, []string{"Proxy  socks5://127.0.0.1:10800"})
	p := u.Progress("Starting", 4)
	p.Set(2, "2 ready")
	p.Finish(toneOK, "done")
	text := out.String()
	if strings.Contains(text, "\x1b") {
		t.Fatalf("escape sequence in plain output: %q", text)
	}
	for _, r := range text {
		if r > 127 {
			t.Fatalf("non-ASCII rune %q in plain output:\n%s", r, text)
		}
	}
	for _, want := range []string{"ktest - connect", "+ ready", "x failed", "READY", "socks5://127.0.0.1:10800", "50%", "Starting"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
}

func TestInteractiveTermColorsBoxesAndRedrawsProgress(t *testing.T) {
	var out bytes.Buffer
	u := &term{w: &out, color: true, unicode: true, live: true}
	u.Box("READY", toneOK, []string{"a", "bb"})
	p := u.Progress("Verifying", 1)
	p.Set(1, "")
	p.Finish(toneWarn, "1 of 2")
	text := out.String()
	for _, want := range []string{"\x1b[32m", "╭", "╯", "▰", "\r\x1b[2K", "•", "!"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %q", want, text)
		}
	}
	// Every boxed line has the same visible width, whatever the colors are.
	var widths []int
	for _, l := range strings.Split(text, "\n") {
		if strings.ContainsAny(l, "╭│╰") {
			widths = append(widths, visibleLen(l))
		}
	}
	for _, w := range widths {
		if w != widths[0] {
			t.Fatalf("ragged box: %v", widths)
		}
	}
}

func TestBarClampsAndWrapTextRespectsWidth(t *testing.T) {
	u := plainTerm(&bytes.Buffer{})
	if got := u.Bar(2, 4, toneOK); got != "####" {
		t.Fatalf("over-full bar %q", got)
	}
	if got := u.Bar(-1, 4, toneOK); got != "...." {
		t.Fatalf("negative bar %q", got)
	}
	for _, l := range wrapText("one two three four five six seven eight nine ten", 12) {
		if len(l) > 12 {
			t.Fatalf("line %q exceeds width", l)
		}
	}
}

func TestMainMenuListsTheThreeActionsOnly(t *testing.T) {
	var out bytes.Buffer
	if code := runInteractive(strings.NewReader("0\n"), &out, t.TempDir()); code != 0 {
		t.Fatal(code)
	}
	text := out.String()
	for _, want := range []string{"Connect", "Diagnose", "Advanced", "Exit", "Status: disconnected"} {
		if !strings.Contains(text, want) {
			t.Fatalf("menu lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Fragment B") {
		t.Fatalf("single methods belong in Advanced:\n%s", text)
	}
}

func TestMainMenuOffersWholePCAndCertificate(t *testing.T) {
	var out bytes.Buffer
	if code := runInteractive(strings.NewReader("0\n"), &out, t.TempDir()); code != 0 {
		t.Fatal(code)
	}
	for _, want := range []string{"Connect, whole PC", "Setup", "Diagnose", "Advanced"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("menu lacks %q:\n%s", want, out.String())
		}
	}
}
