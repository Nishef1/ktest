package main

import (
	"bufio"
	"context"
	"fmt"
	"github.com/Nishef1/ktest/internal/connectionpolicy"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	xterm "golang.org/x/term"

	"github.com/Nishef1/ktest/internal/dnscheck"
	"github.com/Nishef1/ktest/internal/systemtun"
)

// launcher runs one proxy core until ctx ends. dns is the preflight the caller
// already measured, so the core does not repeat a multi-second DNS wait.
type launcher func(ctx context.Context, dns *dnscheck.Result) error

// terminal is the interactive menu. Every action runs in the foreground; Enter
// ends a connection or scan and returns to the menu. Ctrl+C quits the program
// from anywhere, after the running job has cleaned up.
type terminal struct {
	ui *term

	mu             sync.Mutex
	cancel         context.CancelFunc // the running connection or scan
	mainMenuActive bool
	quitting       bool // Ctrl+C: the running job ends and the program quits

	settings     userSettings
	settingsFile string
	options      connectOptions
	notice       string
	noticeTone   tone
}

func (t *terminal) print(format string, args ...any) { t.ui.Printf(format, args...) }

// menuItem is one line of the main menu.
type menuItem struct {
	key, name, desc string
	mode            ConnectionMode                                 // for connect items
	action          func(t *terminal, base string, in *input) bool // false: stdin closed
}

func connectItem(key, name, desc string, mode ConnectionMode) menuItem {
	return menuItem{key: key, name: name, desc: desc, mode: mode, action: func(t *terminal, base string, in *input) bool {
		return t.connectFromMenu(base, in, mode)
	}}
}

// menuSections is the whole menu: connection modes first, tools after.
var menuSections = []struct {
	title string
	items []menuItem
}{
	{"Connection methods", []menuItem{
		connectItem("1", connectionpolicy.Title(string(ModeBalanced)), "Adaptive routing", ModeBalanced),
		connectItem("2", connectionpolicy.Title(string(ModeFast)), "Faster fallback", ModeFast),
		{key: "3", name: connectionpolicy.Title(string(ModeAether)), desc: "WARP / Psiphon", mode: ModeAether, action: func(t *terminal, base string, in *input) bool { return t.aetherMenu(base, in) }},
		connectItem("4", connectionpolicy.Title(string(ModeTor)), "Tor", ModeTor),
		{key: "5", name: connectionpolicy.Title(string(ModeWindscribe)), desc: "Local bridge / through Aether", mode: ModeWindscribe, action: func(t *terminal, base string, in *input) bool { return t.windscribeMenu(base, in) }},
		connectItem("6", connectionpolicy.Title(string(ModePsiphon)), "Psiphon", ModePsiphon),
	}},
	{"Coverage", []menuItem{
		{key: "7", name: "Coverage", action: func(t *terminal, _ string, in *input) bool { return t.chooseCoverage(in) }},
	}},
	{"Tools", []menuItem{
		{key: "8", name: "Diagnose", desc: "Check connection problems", action: func(t *terminal, base string, in *input) bool {
			return t.diagnoseMenu(base, in)
		}},
		{key: "9", name: "Setup", action: func(t *terminal, base string, in *input) bool {
			return t.setup(base, in)
		}},
		{key: "10", name: "CDN scan", action: func(t *terminal, _ string, in *input) bool {
			return t.cdnScanMenu(in)
		}},
		{key: "11", name: "Windscribe test", action: func(t *terminal, base string, in *input) bool { return t.windscribeToolsMenu(base, in) }},
	}},
}

func policyName(mode ConnectionMode) string {
	if mode == ModeWindscribeAether {
		return "Windscribe through Aether"
	}
	for _, section := range menuSections {
		for _, item := range section.items {
			if item.mode == mode && mode != "" {
				return item.name
			}
		}
	}
	return "Balanced"
}

// Setup reports actionable configuration, never connection readiness.
func (t *terminal) setupDescription(base string) string {
	needsCore := t.options.mode == ModePsiphon || t.options.mode == ModeWindscribeAether || (t.options.mode == ModeAether && t.options.exitSocks == "")
	if needsCore && warpState(base) == "no core" {
		return t.ui.Yellow("Exit core needs setup")
	}
	if (t.options.mode == ModeBalanced || t.options.mode == ModeFast) && !t.options.noFront && !t.settings.SkipCertificateOffer {
		switch certState() {
		case "invalid":
			return t.ui.Red("Certificate files need repair")
		case "untrusted", "outdated":
			return t.ui.Yellow("Certificate needs attention")
		case "missing":
			return "Optional certificate setup"
		}
	}
	return "Certificates and exit components"
}

func (t *terminal) mainMenu(base string) {
	u := t.ui
	// Most menus fit 24 rows, but a long warning may wrap to additional
	// rows. Preserve scrollback instead of trapping important options below
	// the bottom of a short alternate-screen terminal.
	requiredRows := 24
	if t.notice != "" {
		noticeRows := len(wrapText(t.notice, max(u.width()-4, 1)))
		requiredRows += max(noticeRows-1, 0)
	}
	u.menuViewHeight(requiredRows)
	u.Printf("%s  %s\n", u.Bold(u.Cyan("ktest")), u.Dim("Free access toolkit"))
	previous := "Default policy: "
	if t.settings.Connect["mode"] != "" {
		previous = "Last policy: "
	}
	u.text("  ", "  ", u.Dim("Disconnected")+" · "+previous+u.Bold(policyName(t.options.mode)))
	u.Printf("%s\n", u.Dim(u.rule(min(u.width()-1, 64))))
	u.text("  "+u.Bold(u.Cyan("Enter"))+"  ", "         ", u.Bold("Connect with "+policyName(t.options.mode)))
	u.Println("")
	for _, s := range menuSections {
		u.Printf("  %s\n", u.Dim(strings.ToUpper(s.title)))
		for _, it := range s.items {
			name := it.name
			desc := it.desc
			if it.key == "9" {
				desc = t.setupDescription(base)
			}
			if it.mode != "" && (it.mode == t.options.mode || (it.mode == ModeWindscribe && t.options.mode.isWindscribe())) && t.settings.Connect["mode"] != "" {
				desc += " · " + u.Cyan("Last used")
			}
			if it.key == "7" {
				name = "Current Mode: Proxy"
				if t.options.tun {
					name = "Current Mode: TUN"
				}
			}
			u.menuOption(it.key, name, desc)
		}
	}
	u.Println("")
	u.menuOption("0", "Exit", "")
	u.Printf("%s\n", u.Dim(u.rule(min(u.width()-1, 64))))
	if t.notice != "" {
		u.text("  ", "  ", u.tinted(t.noticeTone, t.notice))
		t.notice = ""
	} else {
		u.text("  ", "  ", u.Dim("Enter to connect · number to choose an option"))
	}
	u.Printf("  Select > ")
}

func (t *term) menuOption(key, name, description string) {
	prefix := "  " + strings.Repeat(" ", max(2-visibleLen(key), 0)) + t.Bold(t.Cyan(key)) + "  "
	if description == "" || t.width() < 60 {
		t.text(prefix, "      ", t.Bold(name))
		if description != "" {
			t.text("      ", "      ", t.Dim(description))
		}
		return
	}
	prefix += t.Bold(name) + strings.Repeat(" ", max(20-visibleLen(name), 1))
	t.text(prefix, strings.Repeat(" ", visibleLen(prefix)), t.Dim(description))
}

func menuItemCount() int {
	n := 0
	for _, s := range menuSections {
		n += len(s.items)
	}
	return n
}

func findItem(key string) (menuItem, bool) {
	for _, s := range menuSections {
		for _, it := range s.items {
			if it.key == key {
				return it, true
			}
		}
	}
	return menuItem{}, false
}

// input owns stdin, so a running connection can wait for Enter without
// swallowing the next menu choice. quit closes on Ctrl+C.
type input struct {
	lines   <-chan string
	request func() // asks the reader for the next line; nil in tests
	quit    <-chan struct{}
}

// enter asks for a line and returns the channel it arrives on. A job waits on
// it for the Enter that stops it.
func (in *input) enter() <-chan string {
	if in.request != nil {
		in.request()
	}
	return in.lines
}

// asciiDigits maps Persian (U+06F0..), Arabic-Indic (U+0660..) and full-width
// digits to ASCII, so menu numbers typed on a Persian or Arabic keyboard
// layout select the same option.
func asciiDigits(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 0x06F0 && r <= 0x06F9:
			return '0' + (r - 0x06F0)
		case r >= 0x0660 && r <= 0x0669:
			return '0' + (r - 0x0660)
		case r >= 0xFF10 && r <= 0xFF19:
			return '0' + (r - 0xFF10)
		case r == 0x200C || r == 0x200E || r == 0x200F || r == 0xFEFF:
			return -1 // zero-width marks that Persian layouts and pasted text add
		}
		return r
	}, s)
}

func (in *input) read() (string, bool) {
	if in.request != nil {
		in.request()
	}
	select {
	case l, ok := <-in.lines:
		return strings.TrimSpace(asciiDigits(l)), ok
	case <-in.quit:
		return "", false
	}
}

// foreground runs job until it ends, Enter is pressed (when lines is not nil)
// or Ctrl+C. It reports false when stdin closed while waiting.
func (t *terminal) foreground(job func(ctx context.Context), lines ...<-chan string) bool {
	alive, _ := t.run(job, lines...)
	return alive
}

// drainLines drops input typed while a job ran, so a stray Enter cannot answer
// the next menu prompt.
func drainLines(lines <-chan string) {
	for {
		select {
		case _, ok := <-lines:
			if !ok {
				return
			}
		default:
			return
		}
	}
}

// run is foreground that also reports whether the job ended by itself rather
// than being cancelled by Enter. After Ctrl+C it reports alive=false, so every
// menu unwinds and the program quits.
func (t *terminal) run(job func(ctx context.Context), lines ...<-chan string) (alive, finished bool) {
	ctx, cancel := context.WithCancel(context.Background())
	t.mu.Lock()
	t.cancel = cancel
	t.mu.Unlock()
	done := make(chan struct{})
	go func() { job(ctx); close(done) }()
	alive = true
	var enter <-chan string
	if len(lines) > 0 {
		enter = lines[0]
	}
	select {
	case <-done:
		finished = true
	case _, ok := <-enter:
		alive = ok
	case <-ctx.Done(): // Ctrl+C
	}
	cancel()
	<-done
	t.mu.Lock()
	t.cancel = nil
	if t.quitting {
		alive = false
	}
	t.mu.Unlock()
	if alive && enter != nil {
		drainLines(enter)
	}
	return alive, finished
}

// tool runs a finite job (diagnostics, scan, connection). When it ends by
// itself on a menu screen the menu would redraw over its output, so wait for
// Enter first. It reports false only when stdin closed.
func (t *terminal) tool(in *input, job func(ctx context.Context)) bool {
	alive, finished := t.run(job, in.enter())
	if !alive {
		return false
	}
	if finished {
		return t.holdResult(in)
	}
	return true
}

func (t *terminal) holdResult(in *input) bool {
	if !t.ui.live {
		return true
	}
	t.print("\n  Press Enter to return to the menu > ")
	_, ok := in.read()
	return ok
}

// handleInterrupt quits the program on the first Ctrl+C, wherever it is
// pressed. It is never a Back key (Enter and 0 are): a running job is
// cancelled so it can restore the system proxy, TUN routes and helper
// processes, and every prompt then reports closed input.
func (t *terminal) handleInterrupt(quit chan struct{}) {
	t.mu.Lock()
	t.quitting = true
	cancel := t.cancel
	t.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	close(quit)
}

// A second Ctrl+C, or cleanup that outlasts forceQuitAfter, ends the process
// at once. Variables so tests never exit the test binary.
var (
	forceQuitAfter = 10 * time.Second
	forceQuit      = func() { reapTracked(); os.Exit(130) }
)

// lineSource hands out stdin one line at a time, and only when asked.
//
// A console read that is already pending when the menu switches between the
// alternate and the main screen buffer is bound to the buffer that was active
// when it started. Leaving the alternate screen destroys that buffer, and the
// pending read then fails with ERROR_NO_DATA on the next keypress, which looked
// like end of input and closed the program. Reading on demand means no read is
// pending while a menu is drawn or left.
type lineSource struct {
	lines   chan string
	want    chan struct{}
	errors  chan error
	pending atomic.Bool // a read has been requested and not yet delivered or cancelled
}

func newLineSource() *lineSource {
	return &lineSource{lines: make(chan string), want: make(chan struct{}, 1), errors: make(chan error, 1)}
}

// request starts one read unless one is already outstanding.
func (s *lineSource) request() {
	if s.pending.CompareAndSwap(false, true) {
		s.want <- struct{}{}
	}
}

// Windows ReadConsole can return a transient EOF just before delivering
// Ctrl+C, which cancels the pending read. Wait briefly for that notification
// before closing the input; a genuine EOF still exits, and redirected input
// never retries. After a cancelled read nothing is outstanding: the next
// request starts a new one.
func scanMenuInput(reader io.Reader, src *lineSource, finished <-chan struct{}, readInterrupts <-chan struct{}, retryConsoleEOF bool) {
	defer close(src.lines)
	scanner := bufio.NewScanner(reader)
	// The default 64 KiB cap turns long pasted text into a silent EOF.
	// Allow up to 1 MiB, keeping a finite limit for untrusted input.
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for {
		select {
		case <-src.want:
		case <-finished:
			return
		}
	read:
		for {
			if scanner.Scan() {
				line := scanner.Text()
				// Clear the outstanding request before publishing the line. With an
				// unbuffered channel, the receiver may immediately request its next
				// line as soon as this send unblocks; clearing pending after the send
				// can lose that request and deadlock the interactive menu.
				src.pending.Store(false)
				select {
				case src.lines <- line:
				case <-finished:
					return
				}
				break read
			}
			if err := scanner.Err(); err != nil {
				select {
				case src.errors <- fmt.Errorf("terminal input: %w", err):
				default:
				}
				return
			}
			if !retryConsoleEOF {
				return
			}
			select {
			case <-readInterrupts:
				src.pending.Store(false)
				scanner = bufio.NewScanner(reader)
				break read
			case <-finished:
				return
			case <-time.After(200 * time.Millisecond):
				return
			}
		}
	}
}

// runInteractive is the menu. It never changes Windows routing or DNS itself;
// only Whole PC does, after asking for Administrator.
func runInteractive(in io.Reader, out io.Writer, base string) int {
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	return runInteractiveWith(in, out, base, interrupts)
}

// runInteractiveWith takes the Ctrl+C source so tests can inject interrupts.
func runInteractiveWith(in io.Reader, out io.Writer, base string, interrupts <-chan os.Signal) int {
	defer reapTracked() // whatever a session left behind ends with the menu
	settings, path, options, err := loadPreferences(base)
	t := &terminal{ui: newTerm(out), settings: settings, settingsFile: path, options: options}
	defer t.ui.leaveMenu()
	if err != nil {
		t.ui.Line(toneWarn, "Saved settings unavailable; using defaults: %v", err)
	}
	base = options.base
	quit := make(chan struct{})
	readInterrupts := make(chan struct{}, 1)
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		var deadline <-chan time.Time
		for {
			select {
			case <-finished:
				return
			case <-deadline:
				forceQuit()
				return
			case <-interrupts:
				select {
				case readInterrupts <- struct{}{}:
				default:
				}
				if deadline != nil { // second Ctrl+C
					forceQuit()
					return
				}
				t.handleInterrupt(quit)
				deadline = time.After(forceQuitAfter)
			}
		}
	}()
	src := newLineSource()
	defer func() {
		select {
		case err := <-src.errors:
			t.ui.leaveMenu()
			t.ui.Line(toneFail, "%v", err)
		default:
		}
	}()
	consoleInput := false
	if file, ok := in.(*os.File); ok && runtime.GOOS == "windows" {
		consoleInput = xterm.IsTerminal(int(file.Fd()))
	}
	go scanMenuInput(in, src, finished, readInterrupts, consoleInput)
	stdin := &input{lines: src.lines, request: src.request, quit: quit}

	for {
		t.mu.Lock()
		t.mainMenuActive = true
		t.mu.Unlock()
		t.mainMenu(base)
		line, ok := stdin.read()
		t.mu.Lock()
		t.mainMenuActive = false
		t.mu.Unlock()
		if !ok {
			t.print("\n")
			return 0
		}
		switch strings.ToLower(line) {
		case "":
			if !t.connectFromMenu(base, stdin, t.options.mode) {
				return 0
			}
			continue
		case "0", "q", "exit":
			return 0
		}
		it, found := findItem(line)
		if !found {
			t.notice, t.noticeTone = fmt.Sprintf("Unknown option. Use 1-%d, Enter, or 0.", menuItemCount()), toneWarn
			continue
		}
		if !it.action(t, base, stdin) {
			return 0
		}
	}
}

func (t *terminal) menuConnectOptions(base string, mode ConnectionMode) connectOptions {
	o := optionsForMode(t.options, mode)
	o.base = base
	o.stopHint = "Press Enter to disconnect and return to the menu · Ctrl+C quits"
	return o
}

// connectFromMenu offers the certificate first when domain fronting would need
// it, and Administrator for Whole PC. It reports false when stdin closed.
func (t *terminal) connectFromMenu(base string, in *input, mode ConnectionMode) bool {
	t.ui.leaveMenu()
	t.options.mode = mode
	t.rememberConnect("mode", string(mode))
	o := t.menuConnectOptions(base, mode)
	return t.connectWithOptions(in, o)
}

func (t *terminal) connectWithOptions(in *input, o connectOptions) bool {
	mode := o.mode
	t.ui.Note("Policy: %s. Coverage: %s", mode, connectionCoverage(o))
	usesFronting := (mode == ModeBalanced || mode == ModeFast) && !o.noFront
	if state := certState(); state != "ok" && !t.settings.SkipCertificateOffer && usesFronting {
		why := map[string]string{
			"missing":   "Domain fronting (YouTube, X, Instagram, Reddit ...) needs a local certificate that is not set up.",
			"outdated":  "The local certificate needs renewal for its validity period or supported sites.",
			"untrusted": "The local certificate exists but this system does not trust it yet.",
			"invalid":   "The local certificate files cannot be used; open Setup to inspect them.",
		}[state]
		t.ui.Line(toneInfo, "%s", why)
		for {
			t.print("  Type y to set it up now (Windows asks you to confirm), Enter to skip future offers, or 0 to go back > ")
			ans, ok := in.read()
			if !ok {
				return false
			}
			if isBackChoice(ans) {
				return true
			}
			switch {
			case isYes(ans):
				ensureCert(t.ui)
			case ans == "":
				t.settings.SkipCertificateOffer = true
				t.savePreferences()
			default:
				t.ui.Line(toneWarn, "Select y, Enter, or 0 to go back.")
				continue
			}
			break
		}
	}
	if o.tun && !systemtun.IsAdmin() {
		t.ui.Line(toneInfo, "Whole PC needs Administrator.")
		t.print("  Type y to open an Administrator window (Windows asks you to confirm) > ")
		ans, ok := in.read()
		if !ok {
			return false
		}
		if !isYes(ans) {
			t.ui.Line(toneInfo, "Cancelled.")
			return true
		}
		relaunchElevated(t.ui, o)
		return true
	}
	if mode.isWindscribe() {
		t.ui.Box("WINDSCRIBE SETTINGS", toneInfo, []string{
			t.ui.Bold("Connection  ") + "Protocol OpenVPN TCP, port 443",
			t.ui.Bold("Proxy       ") + "Proxy Settings → HTTP, 127.0.0.1, port 10801, no login",
			t.ui.Dim("Not Proxy Gateway. WireGuard, IKEv2 and Stealth ignore this proxy."),
		})
		if o.ws.packetEnabled() {
			t.ui.Note("Click Connect in Windscribe. ktest detects its requested node automatically; no location or IP entry is needed.")
		}
		if mode == ModeWindscribeAether {
			t.ui.Note("Carrier: Aether WARP. Exclude this ktest executable and aether.exe from Windscribe VPN routing; keep this process running while connected.")
		}
	}
	ports := sessionPorts(o)
	wasBusy := busyPorts(ports)
	return t.tool(in, func(ctx context.Context) {
		connectSession(ctx, o, nil, t.ui)
		t.confirmPortsReleased(ports, wasBusy)
	})
}

// sessionPorts are the loopback ports a connection may open.
func sessionPorts(o connectOptions) []int {
	ports := []int{xrayPort}
	for _, addr := range []string{o.listen, o.httpListen} {
		if _, p, err := net.SplitHostPort(addr); err == nil {
			if n, err := strconv.Atoi(p); err == nil {
				ports = append(ports, n)
			}
		}
	}
	// Editable Aether profiles support up to 64 entries, and Gool can start
	// a temporary registration carrier at profile index 80.
	for i := 0; i < 64; i++ {
		ports = append(ports, aetherPort(i))
	}
	ports = append(ports, aetherPort(80))
	return ports
}

func busyPorts(ports []int) map[int]bool {
	busy := map[int]bool{}
	for _, p := range ports {
		if portFree(p) != nil {
			busy[p] = true
		}
	}
	return busy
}

// portReleaseWait is how long a stopped session may take to free its ports.
var portReleaseWait = 3 * time.Second

// confirmPortsReleased checks that every port this session opened is free
// again. Ports that were already taken before it started belong to someone
// else and are ignored. Leftover cores are ended rather than reported.
func (t *terminal) confirmPortsReleased(ports []int, wasBusy map[int]bool) {
	held := func() []int {
		var out []int
		for p := range busyPorts(ports) {
			if !wasBusy[p] {
				out = append(out, p)
			}
		}
		sort.Ints(out)
		return out
	}
	wait := func() []int {
		for deadline := time.Now().Add(portReleaseWait); ; time.Sleep(100 * time.Millisecond) {
			if left := held(); len(left) == 0 || time.Now().After(deadline) {
				return left
			}
		}
	}
	left := wait()
	reaped := 0
	if len(left) > 0 || trackedCount() > 0 {
		reaped = reapTracked()
		left = wait()
	}
	switch {
	case len(left) > 0:
		t.ui.Line(toneWarn, "Port(s) %v are still in use after disconnect; another program may hold them.", left)
	case reaped > 0:
		t.ui.Line(toneWarn, "Ended %d helper process(es) that were still running; all ports are free.", reaped)
	default:
		t.ui.Note("All helper processes stopped; ports are free.")
	}
}
