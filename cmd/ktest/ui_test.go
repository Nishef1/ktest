package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

func TestPlainTermHasNoEscapeSequencesOrUnicodeDecoration(t *testing.T) {
	var out bytes.Buffer
	u := plainTerm(&out)
	u.Heading("connect", "subtitle")
	u.Line(toneOK, "ready")
	u.Line(toneFail, "failed")
	u.Box("READY", toneOK, []string{"Proxy → socks5://127.0.0.1:10800 · TCP"})
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

func TestMainMenuListsModesAndTools(t *testing.T) {
	var out bytes.Buffer
	if code := runInteractive(strings.NewReader("0\n"), &out, t.TempDir()); code != 0 {
		t.Fatal(code)
	}
	text := out.String()
	for _, want := range []string{"CONNECT", "TOOLS", "Proxy", "Diagnose", "Setup", "CDN scan", "Exit"} {
		if !strings.Contains(text, want) {
			t.Fatalf("menu lacks %q:\n%s", want, text)
		}
	}
	for _, gone := range []string{"Advanced", "Fragment B", "Status:"} {
		if strings.Contains(text, gone) {
			t.Fatalf("removed item %q still shown:\n%s", gone, text)
		}
	}
}

func TestOutputFitsTerminalWithoutDroppingDetails(t *testing.T) {
	for _, width := range []int{40, 60, 80, 120} {
		for _, color := range []bool{false, true} {
			var out bytes.Buffer
			u := &term{w: &out, columns: width, color: color, unicode: color}
			token := strings.Repeat("Z", 140)
			u.Line(toneFail, "Connection failed: %s", u.Red(token))
			u.Box("CONNECTION NOT YET VERIFIED", toneWarn, []string{u.Bold("Destination ") + token, "Wait for the VPN application to confirm authentication."})
			u.Printf("  Long prompt %s > ", strings.Repeat("detail ", 30))
			for _, line := range strings.Split(out.String(), "\n") {
				if visibleLen(line) > width {
					t.Fatalf("width=%d color=%t: overflowing line %q", width, color, line)
				}
			}
			plain := ansiPattern.ReplaceAllString(out.String(), "")
			if strings.Count(plain, "Z") != 280 || !strings.Contains(plain, "authentication.") {
				t.Fatalf("width=%d color=%t: details lost: %s", width, color, plain)
			}
		}
	}
}

func TestConnectionFeedPreservesOutcomesAndVerboseError(t *testing.T) {
	var out bytes.Buffer
	feed := &siteEvents{t: plainTerm(&out), verbose: true}
	answered := smartproxy.Event{Host: "api.example.org", Site: "example.org", Path: "Exit: Psiphon", OK: true, Took: 25 * time.Millisecond}
	feed.print(answered)
	first := out.String()
	for _, value := range []string{answered.Site, answered.Path, "25ms"} {
		if !strings.Contains(first, value) {
			t.Fatalf("connection detail %q missing: %s", value, first)
		}
	}
	feed.print(answered)
	if out.String() != first || feed.ok.Load() != 2 {
		t.Fatal("repeated path should be counted without repeating its display")
	}
	feed.print(smartproxy.Event{Host: "198.51.100.23", Path: "local ByeDPI", TCPOnly: true})
	if feed.ok.Load() != 2 || feed.fail.Load() != 0 || feed.tcpOnly.Load() != 1 {
		t.Fatal("TCP establishment changed answered/failed counts")
	}
	err := "first attempt failed: " + strings.Repeat("context ", 20) + "final cause"
	feed.print(smartproxy.Event{Host: "failed.example.org", Site: "failed.example.org", Err: err})
	// Wrapping can insert newlines, but verbose mode must preserve the cause.
	if !strings.Contains(strings.Join(strings.Fields(out.String()), " "), err) {
		t.Fatalf("verbose error was shortened: %s", out.String())
	}
}

func TestLiveProgressKeepsStatusMessagesAndFitsWidth(t *testing.T) {
	var out bytes.Buffer
	u := &term{w: &out, columns: 40, color: true, unicode: true, live: true}
	p := u.Progress("Checking the network", 2)
	u.Line(toneWarn, "route.example.org did not answer")
	p.Set(1, strings.Repeat("detail", 30))
	p.Finish(toneWarn, "One route still unavailable")
	if !strings.Contains(out.String(), "route.example.org did not answer") || u.progressLine != "" {
		t.Fatalf("status lost or progress left active: %q", out.String())
	}
	for _, part := range strings.FieldsFunc(out.String(), func(r rune) bool { return r == '\r' || r == '\n' }) {
		part = strings.ReplaceAll(part, "\x1b[2K", "")
		if visibleLen(part) > 40 {
			t.Fatalf("live output overflowed: %q", part)
		}
	}
}

func TestMenuFitsNarrowAndColoredTerminals(t *testing.T) {
	for _, width := range []int{40, 60, 80, 120} {
		var out bytes.Buffer
		u := &term{w: &out, columns: width, color: true, unicode: true}
		menu := &terminal{out: &out, ui: u}
		menu.mainMenu(t.TempDir())
		for _, line := range strings.Split(out.String(), "\n") {
			if visibleLen(line) > width {
				t.Fatalf("width=%d: overflowing menu line %q", width, line)
			}
		}
		for _, name := range []string{"Balanced", "Aether to Psiphon", "Windscribe", "Proxy", "Diagnose"} {
			if !strings.Contains(ansiPattern.ReplaceAllString(out.String(), ""), name) {
				t.Fatalf("width=%d: missing choice %q", width, name)
			}
		}
	}
}
