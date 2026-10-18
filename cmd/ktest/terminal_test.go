package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type transientEOFReader struct {
	first  bool
	reader io.Reader
	ended  chan struct{}
}

func (r *transientEOFReader) Read(p []byte) (int, error) {
	if !r.first {
		r.first = true
		if r.ended != nil {
			close(r.ended)
		}
		return 0, io.EOF
	}
	return r.reader.Read(p)
}

func TestConsoleInterruptEOFDoesNotCloseMenuInput(t *testing.T) {
	src := newLineSource()
	finished := make(chan struct{})
	interrupts := make(chan struct{}, 1)
	ended := make(chan struct{})
	go func() { <-ended; time.Sleep(10 * time.Millisecond); interrupts <- struct{}{} }()
	go scanMenuInput(&transientEOFReader{reader: strings.NewReader("9\n"), ended: ended}, src, finished, interrupts, true)
	src.request() // cancelled by the Ctrl+C that follows the transient EOF
	// The menu asks again after Ctrl+C; keep asking until the line arrives.
	deadline := time.After(2 * time.Second)
	for {
		src.request()
		select {
		case line, ok := <-src.lines:
			if !ok || line != "9" {
				t.Fatalf("transient Ctrl+C EOF closed the input: %q %v", line, ok)
			}
			close(finished)
			return
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			t.Fatal("no line after the interrupt")
		}
	}
}

func TestRedirectedEOFDoesNotRetryOnAnInterrupt(t *testing.T) {
	src := newLineSource()
	interrupts := make(chan struct{}, 1)
	interrupts <- struct{}{}
	go scanMenuInput(&transientEOFReader{reader: strings.NewReader("must not be read\n")}, src, make(chan struct{}), interrupts, false)
	src.request()
	if line, ok := <-src.lines; ok {
		t.Fatalf("redirected EOF unexpectedly retried: %q", line)
	}
}

type countingReader struct {
	mu    sync.Mutex
	reads int
	r     io.Reader
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.mu.Lock()
	c.reads++
	c.mu.Unlock()
	return c.r.Read(p)
}

func (c *countingReader) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

// A console read pending while the menu leaves the alternate screen fails on
// the next keypress and closes the program, so stdin is only read on request.
func TestStdinIsOnlyReadWhenALineIsRequested(t *testing.T) {
	reader := &countingReader{r: strings.NewReader("1\n2\n3\n")}
	src := newLineSource()
	finished := make(chan struct{})
	defer close(finished)
	go scanMenuInput(reader, src, finished, make(chan struct{}), false)
	time.Sleep(50 * time.Millisecond)
	if reader.count() != 0 {
		t.Fatalf("stdin was read %d times before any request", reader.count())
	}
	src.request()
	src.request() // an outstanding read is not doubled
	if line := <-src.lines; line != "1" {
		t.Fatalf("line = %q", line)
	}
	time.Sleep(50 * time.Millisecond)
	if n := reader.count(); n != 1 {
		t.Fatalf("stdin was read %d times for one request; a read is pending between prompts", n)
	}
	src.request()
	if line := <-src.lines; line != "2" {
		t.Fatalf("line = %q", line)
	}
}

func menuOutput(t *testing.T, input string) string {
	t.Helper()
	t.Setenv("KTEST_SETTINGS_FILE", filepath.Join(t.TempDir(), "settings.json"))
	var out bytes.Buffer
	if code := runInteractive(strings.NewReader(input), &out, t.TempDir()); code != 0 {
		t.Fatal(code)
	}
	return out.String()
}

func TestMenuExits(t *testing.T) {
	for _, in := range []string{"0\n", "q\n", ""} { // "" is stdin closed
		if !strings.Contains(menuOutput(t, in), "Select >") {
			t.Fatalf("no menu for %q", in)
		}
	}
}

func TestSetupCertificateBackReturnsToSetupThenMainMenu(t *testing.T) {
	t.Setenv("KTEST_CA_DIR", t.TempDir())
	out := menuOutput(t, "9\n1\n\n0\n0\n")
	if strings.Count(out, "Certificate health and optional exit components.") != 2 || strings.Count(out, "Free access toolkit") != 2 {
		t.Fatal("certificate Back did not return to Setup before the main menu:", out)
	}
}

func TestSubmenusKeepInvalidInputAndNestedBackInTheirOwnMenu(t *testing.T) {
	t.Setenv("KTEST_CA_DIR", t.TempDir())
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	for _, tc := range []struct {
		name, input, screen string
		visits              int
	}{
		{"coverage", "7\ninvalid\nback\n0\n", "traffic coverage", 2},
		{"diagnostics", "8\ninvalid\n0\n0\n", "Diagnose (Enter", 2},
		{"setup", "9\ninvalid\n0\n0\n", "Certificate health and optional exit components.", 2},
		{"certificate", "9\n1\ninvalid\n0\n0\n0\n", "Certificate health and optional exit components.", 2},
		{"certificate offer", "1\ninvalid\nback\n0\n", "Type y to set it up now", 2},
		{"exit paths", "9\n2\ninvalid\n0\n0\n0\n", "Certificate health and optional exit components.", 2},
		{"CDN provider", "10\ninvalid\n0\n0\n", "Provider: cloudflare", 2},
		{"CDN hostname back", "10\ncloudflare\n0\n0\n0\n", "Provider: cloudflare", 2},
		{"CDN hostname invalid", "10\ncloudflare\nhttps://invalid\n0\n0\n", "Provider: cloudflare", 2},
		{"Windscribe target", "11\n2\nback\n0\n0\n", "Location or TCP IP", 1},
		{"Windscribe SNI back", "11\n2\nexample\n0\n0\n0\n0\n", "Location or TCP IP", 2},
		{"Windscribe SNI invalid", "11\n2\nexample\nhttps://invalid\n0\n0\n0\n", "Location or TCP IP", 2},
		{"Windscribe modes", "5\ninvalid\n0\n0\n", "Windscribe >", 2},
		{"Aether method back", "3\n2\n0\n0\n0\n", "Aether >", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := menuOutput(t, tc.input)
			if strings.Count(out, "Free access toolkit") != 2 || strings.Count(out, tc.screen) != tc.visits || strings.Contains(out, "Unknown option") {
				t.Fatal("submenu skipped a parent or exited unexpectedly:", out)
			}
		})
	}
}

func TestCtrlCAtNestedToolPromptReturnsToToolBeforeMainMenu(t *testing.T) {
	for _, tool := range []string{"cdn", "windscribe"} {
		t.Run(tool, func(t *testing.T) {
			var out bytes.Buffer
			menu := &terminal{ui: plainTerm(&out)}
			lines, back := make(chan string), make(chan struct{})
			in := &input{lines: lines, back: back}
			done := make(chan bool, 1)
			go func() {
				if tool == "cdn" {
					done <- menu.cdnScanMenu(in)
				} else {
					done <- menu.windscribeTestMenu("unused", in)
				}
			}()
			first := "example"
			if tool == "cdn" {
				first = "cloudflare"
			}
			select {
			case lines <- first:
			case <-time.After(time.Second):
				t.Fatal("tool prompt unavailable")
			}
			select {
			case back <- struct{}{}:
			case <-time.After(time.Second):
				t.Fatal("nested prompt did not receive Ctrl+C")
			}
			select {
			case lines <- "0":
			case <-time.After(time.Second):
				t.Fatal("Ctrl+C skipped the tool menu")
			}
			select {
			case alive := <-done:
				if !alive || in.interrupted {
					t.Fatal("nested Ctrl+C escaped the parent menu")
				}
			case <-time.After(time.Second):
				t.Fatal("tool failed to go back")
			}
		})
	}
}

func TestMenuKeysAreUniqueAndContiguous(t *testing.T) {
	want := 1
	for _, s := range menuSections {
		for _, it := range s.items {
			if it.key != strconv.Itoa(want) || it.action == nil {
				t.Fatalf("item %q (%s): want key %d with an action", it.key, it.name, want)
			}
			want++
		}
	}
}

func TestEnterConnectsWithSavedPolicyWithoutRepeatingSelection(t *testing.T) {
	t.Setenv("KTEST_CA_DIR", t.TempDir())
	t.Setenv("KTEST_SETTINGS_FILE", filepath.Join(t.TempDir(), "settings.json"))
	settings, path, _, err := loadPreferences(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	settings.Connect["mode"] = "fast"
	if err := saveSettings(path, settings); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	// EOF at the certificate offer ends the operation before networking/UAC.
	if code := runInteractive(strings.NewReader("\n"), &output, t.TempDir()); code != 0 {
		t.Fatal(code)
	}
	if !strings.Contains(output.String(), "Connect with Fast") || !strings.Contains(output.String(), "Policy: fast.") || strings.Contains(output.String(), "Unknown option") {
		t.Fatalf("Enter did not select the saved policy: %s", output.String())
	}
}

func TestUnknownOptionNamesTheRange(t *testing.T) {
	if out := menuOutput(t, "42\n0\n"); !strings.Contains(out, "Unknown option. Use 1-11, Enter, or 0.") {
		t.Fatal(out)
	}
}

func TestMenuDoesNotAdvertiseConfiguredExitsAsConnected(t *testing.T) {
	if out := menuOutput(t, "0\n"); !strings.Contains(out, "Disconnected") || strings.Contains(out, "exit paths (WARP/Psiphon):") || strings.Contains(out, "READY") {
		t.Fatal("configuration was presented as a connection:", out)
	}
}

func TestCoverageSaveFailureDoesNotClaimSuccess(t *testing.T) {
	var out bytes.Buffer
	menu := &terminal{ui: plainTerm(&out), options: connectOptions{tun: true}}
	lines := make(chan string, 1)
	lines <- "1"
	if !menu.chooseCoverage(&input{lines: lines}) {
		t.Fatal("coverage selection ended the menu")
	}
	menu.mainMenu(t.TempDir())
	if menu.options.tun || !strings.Contains(out.String(), "Not saved:") || strings.Contains(out.String(), "Saved: Proxy") {
		t.Fatal("unsaved coverage change was presented as durable:", out.String())
	}
}

func TestMenuCoveragePreservesPolicyAndKeepsWindscribeSeparate(t *testing.T) {
	for _, wholePC := range []bool{false, true} {
		var output bytes.Buffer
		menu := &terminal{options: connectOptions{tun: wholePC}, ui: plainTerm(&output)}
		menu.mainMenu(t.TempDir())
		want := "7 Current Mode: Proxy"
		if wholePC {
			want = "7 Current Mode: TUN"
		}
		found := false
		for _, line := range strings.Split(output.String(), "\n") {
			if strings.Join(strings.Fields(line), " ") == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("wholePC=%t: expected only %q on coverage row:\n%s", wholePC, want, output.String())
		}
	}
	for _, mode := range []ConnectionMode{ModeBalanced, ModeFast, ModeAether, ModePsiphon, ModeTor, ModeWindscribe} {
		for _, wholePC := range []bool{false, true} {
			menu := &terminal{options: connectOptions{tun: wholePC}}
			o := menu.menuConnectOptions("example-base", mode)
			if o.mode != mode || o.tun != (wholePC && mode != ModeWindscribe) {
				t.Fatalf("mode=%s wholePC=%t produced mode=%s tun=%t", mode, wholePC, o.mode, o.tun)
			}
		}
	}
}

func TestElevationPreservesEffectivePolicyAcrossUserProfiles(t *testing.T) {
	o := defaultConnectOptions("example-base")
	o.mode, o.tun = ModeTor, true
	o.aiExtra, o.exitSocks = "sensitive.example", "127.0.0.1:19001"
	o.noDirect, o.noFront, o.verbose = true, true, true
	o.ws.sni, o.ws.direct = "python.org", false
	o.cert = true // already performed by the parent; never replay it
	args := elevatedConnectArgs(o)
	if args[0] != "connect" || args[1] != elevatedSessionArg {
		t.Fatalf("child could load another user's defaults: %v", args)
	}
	child := defaultConnectOptions("another-admin-package")
	child.mode, child.aiExtra = ModeFast, "other-user.example"
	flags := connectFlagSet(&child)
	if err := flags.Parse(args[2:]); err != nil {
		t.Fatal(err)
	}
	// Ignore the completed one-shot action when comparing the full snapshot.
	o.cert = false
	if child != o {
		t.Fatalf("effective options changed across UAC:\nchild: %+v\nparent: %+v", child, o)
	}
	if err := validateConnectOptions(child); err != nil {
		t.Fatal(err)
	}
}

func TestAetherMethodWarningDoesNotStick(t *testing.T) {
	var out bytes.Buffer
	menu := &terminal{ui: plainTerm(&out)}
	lines := make(chan string, 3)
	lines <- "99"
	lines <- "x"
	lines <- "0"
	if !menu.chooseAetherMethod(&input{lines: lines}) {
		t.Fatal("method menu ended the program")
	}
	if got := strings.Count(out.String(), "Select 1-"); got != 2 {
		t.Fatalf("stale warning repeated %d times, want one per bad answer (2):\n%s", got, out.String())
	}
}

func TestInputTypedDuringAJobDoesNotAnswerTheNextPrompt(t *testing.T) {
	menu := &terminal{ui: plainTerm(io.Discard)}
	lines := make(chan string, 2)
	lines <- "" // Enter that stops the job
	lines <- "" // second Enter pressed while it was stopping
	alive, finished := menu.run(func(ctx context.Context) { <-ctx.Done() }, lines)
	if !alive || finished {
		t.Fatalf("alive=%t finished=%t", alive, finished)
	}
	select {
	case line := <-lines:
		t.Fatalf("stale input %q survived the job", line)
	default:
	}
}

func TestFinishedJobWaitsForEnterOnlyOnLiveMenus(t *testing.T) {
	plain := &terminal{ui: plainTerm(io.Discard)}
	if !plain.holdResult(&input{lines: make(chan string)}) {
		t.Fatal("plain output must not wait")
	}
	var out bytes.Buffer
	live := &terminal{ui: &term{w: &out, live: true}}
	lines := make(chan string, 1)
	lines <- ""
	if !live.holdResult(&input{lines: lines}) || !strings.Contains(out.String(), "Press Enter to return") {
		t.Fatal("live menu redrew over finished output without waiting:", out.String())
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) count(s string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Count(b.buf.String(), s)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// session drives runInteractiveWith with a live stdin pipe and injected Ctrl+C.
type session struct {
	t          *testing.T
	out        *syncBuffer
	stdin      *io.PipeWriter
	interrupts chan os.Signal
	code       chan int
}

func startSession(t *testing.T) *session {
	t.Helper()
	t.Setenv("KTEST_SETTINGS_FILE", filepath.Join(t.TempDir(), "settings.json"))
	t.Setenv("KTEST_CA_DIR", t.TempDir())
	t.Setenv("KTEST_WARP_DIR", t.TempDir())
	r, w := io.Pipe()
	s := &session{t: t, out: &syncBuffer{}, stdin: w, interrupts: make(chan os.Signal, 1), code: make(chan int, 1)}
	go func() { s.code <- runInteractiveWith(r, s.out, t.TempDir(), s.interrupts) }()
	t.Cleanup(func() { w.Close() })
	return s
}

func (s *session) waitFor(text string, count int) {
	s.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for s.out.count(text) < count {
		if time.Now().After(deadline) {
			s.t.Fatalf("timed out waiting for %d x %q:\n%s", count, text, s.out.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (s *session) send(line string) { fmt.Fprintln(s.stdin, line) }

func (s *session) ctrlC() { s.interrupts <- os.Interrupt }

func (s *session) expectExit() {
	s.t.Helper()
	select {
	case code := <-s.code:
		if code != 0 {
			s.t.Fatalf("exit code %d", code)
		}
	case <-time.After(3 * time.Second):
		s.t.Fatalf("program did not exit:\n%s", s.out.String())
	}
}

func (s *session) expectRunning() {
	s.t.Helper()
	select {
	case code := <-s.code:
		s.t.Fatalf("program exited (%d) but should have stayed open:\n%s", code, s.out.String())
	case <-time.After(100 * time.Millisecond):
	}
}

func TestCtrlCAtTheIdleMainMenuExitsCleanly(t *testing.T) {
	s := startSession(t)
	s.waitFor("Select >", 1)
	s.ctrlC()
	s.expectExit()
}

func TestPersianAndArabicDigitsSelectMenuOptions(t *testing.T) {
	s := startSession(t)
	s.waitFor("Select >", 1)
	s.send("۳") // Persian 3: Aether
	s.waitFor("Aether >", 1)
	s.send("٠") // Arabic-Indic 0: back
	s.waitFor("Select >", 2)
	s.send("۰") // Persian 0: exit
	s.expectExit()
}

func TestAsciiDigitsNormalizesLayoutsAndInvisibleMarks(t *testing.T) {
	for in, want := range map[string]string{"۱۰": "10", "٣": "3", "１１": "11", "1\u200c": "1", "\ufeff7": "7", "cloudflare": "cloudflare"} {
		if got := asciiDigits(in); got != want {
			t.Fatalf("asciiDigits(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMenuInputAcceptsLongPastedLine(t *testing.T) {
	src := newLineSource()
	done := make(chan struct{})
	defer close(done)
	input := strings.Repeat("x", 70<<10)
	go scanMenuInput(strings.NewReader(input+"\n"), src, done, make(chan struct{}), false)
	src.request()
	got, ok := <-src.lines
	if !ok || got != input {
		t.Fatalf("pasted input truncated or treated as EOF: len=%d, ok=%t", len(got), ok)
	}
}
func TestMenuInputReportsOversizedLine(t *testing.T) {
	src := newLineSource()
	go scanMenuInput(strings.NewReader(strings.Repeat("x", 1<<20)+"\n"), src, make(chan struct{}), make(chan struct{}), false)
	src.request()
	if _, ok := <-src.lines; ok {
		t.Fatal("oversized input accepted")
	}
	select {
	case err := <-src.errors:
		if !strings.Contains(err.Error(), "token too long") {
			t.Fatalf("unexpected scanner error: %v", err)
		}
	default:
		t.Fatal("menu closed without an input error")
	}
}

func TestLongMenuNoticeUsesScrollableScreen(t *testing.T) {
	var out bytes.Buffer
	u := &term{w: &out, columns: 80, live: true}
	menu := &terminal{ui: u, notice: strings.Repeat("A detailed connection warning. ", 30)}
	menu.mainMenu(t.TempDir())
	if strings.Contains(out.String(), "\x1b[?1049h") {
		t.Fatal("wrapped notice entered an alternate screen too short to scroll")
	}
	if !strings.Contains(out.String(), "A detailed connection warning.") {
		t.Fatal("notice disappeared when the scrollable fallback was selected")
	}
}

func TestCtrlCQuitsFromAnywhereInTheMenus(t *testing.T) {
	for _, tc := range []struct {
		name, wait string
		keys       []string
	}{
		{"main menu", "Select >", nil},
		{"submenu", "Windscribe >", []string{"5"}},
		{"nested submenu", "Windscribe test >", []string{"5", "4"}},
		{"nested prompt", "Provider: cloudflare", []string{"10"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := startSession(t)
			s.waitFor("Select >", 1)
			for _, k := range tc.keys {
				s.send(k)
			}
			s.waitFor(tc.wait, 1)
			s.ctrlC()
			s.expectExit()
		})
	}
}

func TestEnterKeepsItsMeaningInMenus(t *testing.T) {
	s := startSession(t)
	s.waitFor("Select >", 1)
	s.send("5")
	s.waitFor("Windscribe >", 1)
	s.send("") // Enter is not Back
	s.waitFor("Select 1-4, or 0", 1)
	s.send("0")
	s.waitFor("Select >", 2)
	s.send("0")
	s.expectExit()
}


func TestWindscribeMenuOptionThreeIsExplicitlyExperimental(t *testing.T) {
	out := menuOutput(t, "5\n3\n0\n0\n0\n")
	for _, want := range []string{
		"Zapret2 (Windows experimental test)",
		"Diagnostics and tests",
		"Windows packet-layer A/B test; does NOT connect Windscribe VPN.",
		"Free access toolkit",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("Windscribe option three did not explain its experimental limitations, missing %q:\n%s", want, out)
		}
	}
}

