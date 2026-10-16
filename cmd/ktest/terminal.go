package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Nishef1/ktest/internal/dnscheck"
	"github.com/Nishef1/ktest/internal/quickcheck"
	"github.com/Nishef1/ktest/internal/revive"
	"github.com/Nishef1/ktest/internal/systemtun"
)

type cliSession struct {
	choice string
	name   string
	port   int
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

type tunSession struct {
	cancel context.CancelFunc
	done   chan struct{}
}

type terminal struct {
	out         io.Writer
	ui          *term
	mu          sync.Mutex
	active      *cliSession
	tun         *tunSession
	status      string
	results     []quickcheck.Result
	assessments []quickcheck.Assessment
	scanCancel  context.CancelFunc
	connect     context.CancelFunc // set while the connect view runs

	certDeclined bool // the user skipped the certificate offer this session
}

func (t *terminal) print(format string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, _ = fmt.Fprintf(t.out, format, args...)
}

func (t *terminal) current() *cliSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.active
}

func (t *terminal) setStatus(s *cliSession, status string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active == s {
		t.status = status
	}
}

func (t *terminal) stop() bool {
	t.mu.Lock()
	scanCancel := t.scanCancel
	t.mu.Unlock()
	if scanCancel != nil {
		scanCancel()
		t.print("Cancelling CDN scan; current requests will finish or time out.\n")
		return true
	}
	if !t.stopTunIfActive() {
		return false
	}
	t.mu.Lock()
	s := t.active
	t.mu.Unlock()
	if s == nil {
		t.print("\nNo active mode to stop.\n")
		return true
	}
	t.print("\nStopping %s...\n", s.name)
	s.cancel()
	select {
	case <-s.done:
		t.mu.Lock()
		if t.active == s {
			t.active = nil
			t.status = "disconnected"
		}
		t.mu.Unlock()
		t.print("Stopped. You can select another mode.\n")
		return true
	case <-time.After(5 * time.Second):
		t.print("Could not confirm shutdown; refusing to start another core.\n")
		return false
	}
}

// launcher runs one proxy core until ctx ends. dns is the preflight the caller
// already measured, so the core does not repeat a multi-second DNS wait.
type launcher func(ctx context.Context, dns *dnscheck.Result) error

// terminalMode prepares one single-method core for the Advanced menu.
func terminalMode(choice string, base string, output io.Writer) (launcher, int, string, error) {
	core := filepath.Join(base, "cores")
	profile := filepath.Join(base, "profiles", "Serverless-for-Iran.json")
	if choice == "1" || choice == "2" {
		bin := filepath.Join(core, "xray")
		if runtime.GOOS == "windows" {
			bin += ".exe"
		}
		for _, file := range []string{bin, profile} {
			if info, err := os.Stat(file); err != nil || info.IsDir() {
				return nil, 0, "", fmt.Errorf("missing %s; download and extract the full portable ZIP", file)
			}
		}
		variant := "B"
		if choice == "2" {
			variant = "A"
		}
		return func(ctx context.Context, dns *dnscheck.Result) error {
			return revive.Run(ctx, revive.Config{
				XrayBinary: bin,
				Profile:    profile,
				Variant:    variant,
				AssetDir:   core,
				Output:     output,
				DNS:        dns,
			})
		}, xrayPort, "Xray Fragment " + variant, nil
	}
	if choice == "3" || choice == "4" {
		bin := byeDPIBinary(base)
		if info, err := os.Stat(bin); err != nil || info.IsDir() {
			return nil, 0, "", fmt.Errorf("missing %s; download the complete portable ZIP", bin)
		}
		strategy := []string{"--tlsrec", "3+s"}
		label := "ByeDPI TLS record slicing"
		if choice == "3" {
			strategy = []string{"--auto=torst", "--timeout", "3", "--tlsrec", "3+s"}
			label = "ByeDPI adaptive"
		}
		return byeDPILauncher(bin, byeDPIPort, strategy, output), byeDPIPort, label, nil
	}
	return nil, 0, "", fmt.Errorf("unknown option %q", choice)
}

func (t *terminal) start(choice, base string) {
	if t.current() != nil && !t.stop() {
		return
	}
	launch, port, label, err := terminalMode(choice, base, t.out)
	if err != nil {
		t.ui.Line(toneFail, "Cannot start: %v", err)
		return
	}
	if err := portFree(port); err != nil {
		t.ui.Line(toneFail, "Cannot start %s: %v", label, err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &cliSession{
		choice: choice, name: label, port: port, ctx: ctx, cancel: cancel, done: make(chan struct{}),
	}
	t.mu.Lock()
	t.active, t.status, t.results, t.assessments = s, "starting "+label, nil, nil
	t.mu.Unlock()
	t.ui.Line(toneInfo, "Starting %s (the menu stays usable)", t.ui.Bold(label))
	// The DNS preflight runs inside the session goroutine: a network that
	// silently drops 8.8.8.8 must not freeze the menu or the Ctrl+C handler.
	go func() {
		var err error
		dns := dnscheck.CheckGoogleDNS(ctx)
		if ctx.Err() == nil {
			err = launch(ctx, &dns)
		}
		close(s.done)
		if ctx.Err() != nil {
			return
		}
		t.mu.Lock()
		if t.active == s {
			t.status = fmt.Sprintf("core stopped: %v", err)
			t.active = nil
		}
		t.mu.Unlock()
		t.ui.Line(toneFail, "%s stopped: %v", label, err)
	}()
	go t.waitAndCheck(ctx, s)
}

// coreReadyLimit covers the DNS preflight, "xray version", "xray run -test"
// (the first launch of an unsigned core can sit in antivirus scanning) and the
// listener opening. A fixed few seconds misreported slow starts as failures.
const coreReadyLimit = 45 * time.Second

func (t *terminal) waitAndCheck(ctx context.Context, s *cliSession) {
	if waitForPort(ctx, s.done, s.port, coreReadyLimit) {
		t.setStatus(s, fmt.Sprintf("%s on 127.0.0.1:%d, checking websites", s.name, s.port))
		t.ui.Line(toneOK, "%s listening on 127.0.0.1:%d; verifying YouTube and Google", s.name, s.port)
		t.check(ctx, s)
		return
	}
	select {
	case <-ctx.Done():
	case <-s.done:
		// The core already reported why it stopped.
	default:
		t.setStatus(s, "proxy did not open; check core errors")
		t.ui.Line(toneFail, "%s: proxy did not open at 127.0.0.1:%d within %s", s.name, s.port, coreReadyLimit)
	}
}

func (t *terminal) check(ctx context.Context, s *cliSession) {
	// Check ordinary OS routing and the selected SOCKS path at the same time.
	// A third-party VPN may transparently carry either one, so the user keeps
	// control of VPN state for a meaningful comparison.
	proxied, compared := measure(ctx, s.port)
	if ctx.Err() != nil || t.current() != s {
		return
	}
	candidates := 0
	for _, a := range compared {
		switch a.Kind {
		case "candidate":
			candidates++
			t.ui.Line(toneOK, "%-9s blocked directly, open through ktest (bypass confirmed)", a.Target)
		case "already_open":
			t.ui.Line(toneInfo, "%-9s open through ktest and also directly; no bypass attributed", a.Target)
		case "proxy_regression":
			t.ui.Line(toneWarn, "%-9s open directly but failing through this method (DNS or route)", a.Target)
		case "baseline_unknown":
			t.ui.Line(toneInfo, "%-9s open through ktest; direct check did not finish", a.Target)
		default:
			t.ui.Line(toneFail, "%-9s not reachable through this method %s", a.Target, t.ui.Dim(trimDetail(a.Detail)))
		}
	}
	t.mu.Lock()
	if t.active == s {
		t.results = proxied
		t.assessments = compared
		t.status = fmt.Sprintf("%s on 127.0.0.1:%d (%d/%d verified)", s.name, s.port, proxiedPassCount(proxied), len(proxied))
	}
	t.mu.Unlock()
	if candidates == 0 {
		t.ui.Note("No new access verified on this network. For the best result use Connect, which races every method.")
	}
}

// mainMenu and advancedMenu are the only two screens.
func (t *terminal) mainMenu() {
	u := t.ui
	t.mu.Lock()
	status := t.status
	t.mu.Unlock()
	u.Heading("free access toolkit", "")
	state := u.Dim(status)
	if status != "disconnected" {
		state = u.Green(status)
	}
	u.Printf("  Status: %s\n\n", state)
	u.Printf("  %s  %s  %s\n", u.Bold(u.Cyan("1")), u.Bold("Connect          "), u.Dim("try every method, keep what works (recommended)"))
	u.Printf("  %s  %s  %s\n", u.Bold(u.Cyan("2")), u.Bold("Connect, whole PC"), u.Dim("the same, for every application (Windows, Administrator)"))
	u.Printf("  %s  %s  %s\n", u.Bold(u.Cyan("3")), u.Bold("Diagnose         "), u.Dim("what is this network doing? DNS, SNI, packet cutting"))
	u.Printf("  %s  %s  %s\n", u.Bold(u.Cyan("4")), u.Bold("Setup            "), u.Dim("certificate for domain fronting, WARP exit for Telegram"))
	u.Printf("  %s  %s  %s\n", u.Bold(u.Cyan("5")), u.Bold("Advanced         "), u.Dim("single methods, CDN scan"))
	if t.current() != nil {
		u.Printf("  %s  %s  %s\n", u.Bold(u.Cyan("6")), u.Bold("Stop             "), u.Dim("stop the running method"))
	}
	u.Printf("  %s  %s\n\n", u.Bold(u.Cyan("0")), u.Bold("Exit      "))
	u.Printf("  Select > ")
}

func (t *terminal) advancedMenu() {
	u := t.ui
	u.Heading("advanced", "Single methods listen on 127.0.0.1:10808 (Xray) or :10809 (ByeDPI).")
	for _, r := range [][2]string{
		{"1", "Xray fragment B"}, {"2", "Xray fragment A"},
		{"3", "ByeDPI adaptive"}, {"4", "ByeDPI TLS record slicing"},
		{"5", "CDN IP candidates (Cloudflare scan)"}, {"6", "System-wide TUN (Windows, Administrator, beta)"},
		{"7", "Stop the running method"}, {"8", "Re-test YouTube and Google"},
		{"0", "Back"},
	} {
		u.Printf("  %s  %s\n", u.Bold(u.Cyan(r[0])), r[1])
	}
	u.Printf("\n  Select > ")
}

// runInteractive is the menu. Connect runs in the foreground with its own
// progress view; the Advanced screen keeps the single-method sessions.
// It deliberately keeps Windows routing/DNS unchanged.
func runInteractive(in io.Reader, out io.Writer, base string) int {
	t := &terminal{out: out, ui: newTerm(out), status: "disconnected"}
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	quitSignal := make(chan struct{})
	defer close(quitSignal)
	go func() {
		for {
			select {
			case <-quitSignal:
				return
			case <-interrupts:
				t.mu.Lock()
				connect := t.connect
				t.mu.Unlock()
				if connect != nil {
					connect() // the connect view prints its own summary
					continue
				}
				t.print("\nCtrl+C: stopping the active method; the menu remains available.\n")
				t.stop()
			}
		}
	}()
	// One reader owns stdin, so the connect view can wait for Enter without
	// swallowing the next menu choice.
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(in)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	readLine := func() (string, bool) {
		l, ok := <-lines
		return strings.TrimSpace(l), ok
	}

	for {
		t.mainMenu()
		line, ok := readLine()
		if !ok {
			t.stopIfActive()
			return 0
		}
		switch line {
		case "":
			// Asynchronous output can visually displace the prompt; an empty
			// Enter is never an invalid choice.
			continue
		case "1", "2":
			if t.current() != nil && !t.stop() {
				continue
			}
			if !t.connectFromMenu(base, lines, readLine, line == "2") {
				return 0
			}
		case "3":
			runDoctorView(t.ui, base, false)
		case "4":
			t.setup(base, readLine)
		case "5":
			if !t.advanced(base, readLine) {
				return 0
			}
		case "6", "s", "S":
			t.stop()
		case "0", "q", "Q":
			if !t.stopIfActive() {
				continue
			}
			return 0
		default:
			t.ui.Line(toneWarn, "Unknown option. Select 1-5, or 0 to exit.")
		}
	}
}

// connectFromMenu is Connect (or Connect for the whole PC) with the certificate
// offered first when domain fronting would need it. It reports false when stdin
// closed.
func (t *terminal) connectFromMenu(base string, lines <-chan string, readLine func() (string, bool), tun bool) bool {
	if state := certState(); state != "ok" && !t.certDeclined {
		why := map[string]string{
			"missing":   "Domain fronting (YouTube, X, Instagram, Reddit ...) needs a local certificate that is not set up.",
			"outdated":  "The local certificate predates sites this ktest can front.",
			"untrusted": "The local certificate exists but this system does not trust it yet.",
		}[state]
		t.ui.Line(toneInfo, "%s", why)
		t.print("  Type YES to set it up now (Windows asks you to confirm), or press Enter to skip > ")
		ans, ok := readLine()
		if !ok {
			return false
		}
		if strings.EqualFold(ans, "YES") {
			ensureCert(t.ui)
		} else {
			t.certDeclined = true
		}
	}
	if tun && !systemtun.IsAdmin() {
		t.ui.Line(toneInfo, "The whole-PC mode needs Administrator.")
		t.print("  Type YES to open an Administrator window (Windows asks you to confirm) > ")
		ans, ok := readLine()
		if !ok {
			return false
		}
		if !strings.EqualFold(ans, "YES") {
			t.ui.Line(toneInfo, "Cancelled.")
			return true
		}
		o := defaultConnectOptions(base)
		relaunchElevated(t.ui, o)
		return true
	}
	return t.runConnect(base, lines, tun)
}

// runConnect shows the connect view until the session ends or the user presses
// Enter / Ctrl+C. It reports false when stdin closed.
func (t *terminal) runConnect(base string, lines <-chan string, tun bool) bool {
	ctx, cancel := context.WithCancel(context.Background())
	t.mu.Lock()
	t.connect = cancel
	t.mu.Unlock()
	o := defaultConnectOptions(base)
	o.stopHint = "Press Enter or Ctrl+C to disconnect"
	o.tun = tun
	done := make(chan int, 1)
	go func() { done <- connectSession(ctx, o, nil, t.ui) }()
	alive := true
	select {
	case <-done:
	case _, ok := <-lines:
		alive = ok
		cancel()
		<-done
	case <-ctx.Done(): // Ctrl+C
		<-done
	}
	cancel()
	t.mu.Lock()
	t.connect = nil
	t.mu.Unlock()
	return alive
}

// advanced is the single-method screen. It reports false when stdin closed.
func (t *terminal) advanced(base string, readLine func() (string, bool)) bool {
	for {
		t.advancedMenu()
		line, ok := readLine()
		if !ok {
			t.stopIfActive()
			return false
		}
		switch line {
		case "":
			continue
		case "1", "2", "3", "4":
			t.start(line, base)
		case "5":
			t.ui.Line(toneInfo, "Scanning up to 300 official Cloudflare IPs; Ctrl+C cancels.")
			scanCtx, scanStop := context.WithCancel(context.Background())
			t.mu.Lock()
			t.scanCancel = scanStop
			t.mu.Unlock()
			runQuickScanContext(scanCtx, []string{"-provider", "cloudflare"})
			scanStop()
			t.mu.Lock()
			t.scanCancel = nil
			t.mu.Unlock()
		case "6":
			t.toggleTun(base, readLine)
		case "7", "s", "S":
			t.stop()
		case "8", "t", "T":
			s := t.current()
			if s == nil {
				t.ui.Line(toneWarn, "No active method; start one of 1-4 first.")
			} else {
				go t.check(s.ctx, s)
			}
		case "0", "b", "B":
			return true
		default:
			t.ui.Line(toneWarn, "Unknown option. Select 1-8, or 0 to go back.")
		}
	}
}

func (t *terminal) toggleTun(base string, readLine func() (string, bool)) {
	t.mu.Lock()
	exists := t.tun != nil
	t.mu.Unlock()
	if exists {
		t.stopTunIfActive()
		return
	}
	active := t.current()
	if active == nil {
		t.ui.Line(toneWarn, "Start and verify a single method (1-4) first.")
		return
	}
	t.mu.Lock()
	verified := false
	for _, result := range t.assessments {
		if result.Target == "YouTube" && result.Kind == "candidate" {
			verified = true
		}
	}
	t.mu.Unlock()
	if !verified {
		t.ui.Line(toneWarn, "YouTube has not been proven newly reachable through ktest. Refusing to change system routes.")
		return
	}
	t.ui.Line(toneInfo, "Rechecking YouTube directly before TUN startup...")
	directCtx, stopBaseline := context.WithTimeout(context.Background(), 9*time.Second)
	recheck := quickcheck.RunDirect(directCtx, 4*time.Second)
	stopBaseline()
	for _, result := range recheck {
		if result.Target == "YouTube" && result.Success {
			verified = false
		}
	}
	if !verified {
		t.ui.Line(toneWarn, "YouTube now works without ktest. TUN would be an unverified benefit; refusing activation.")
		return
	}
	t.ui.Line(toneWarn, "BETA: TCP-wide TUN, Administrator required; UDP except DNS is blocked.")
	t.ui.Note("May disrupt Windows and other VPNs. Routes should restore when stopped.")
	t.print("  Type YES to modify system-wide routes > ")
	answer, ok := readLine()
	if !ok || !strings.EqualFold(answer, "YES") {
		t.ui.Line(toneInfo, "Cancelled.")
		return
	}
	t.startTun(base, active.port)
}

func (t *terminal) stopIfActive() bool {
	if t.current() != nil {
		return t.stop()
	}
	return t.stopTunIfActive()
}

func (t *terminal) stopTunIfActive() bool {
	t.mu.Lock()
	ts := t.tun
	t.mu.Unlock()
	if ts == nil {
		return true
	}
	t.print("Stopping Windows TUN and restoring routes...\n")
	ts.cancel()
	select {
	case <-ts.done:
		t.mu.Lock()
		if t.tun == ts {
			t.tun = nil
		}
		t.mu.Unlock()
		t.print("TUN process stopped. Windows should restore its routes.\n")
		return true
	case <-time.After(12 * time.Second):
		t.print("Could not verify TUN shutdown. Do not switch proxy cores until routes recover.\n")
		return false
	}
}

func (t *terminal) startTun(base string, socksPort int) {
	ctx, cancel := context.WithCancel(context.Background())
	ts := &tunSession{cancel: cancel, done: make(chan struct{})}
	t.mu.Lock()
	t.tun = ts
	t.mu.Unlock()
	coreDir := filepath.Join(base, "cores")
	go func() {
		err := systemtun.Start(ctx, coreDir, socksPort, t.out)
		close(ts.done)
		t.mu.Lock()
		if t.tun == ts {
			t.tun = nil
		}
		t.mu.Unlock()
		if ctx.Err() == nil {
			t.print("TUN exited: %v\n", err)
		}
	}()
	// Verify actual system-routed HTTPS and automatically revert on total
	// failure, rather than leaving the user's Windows network stranded.
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-ts.done:
			return
		case <-time.After(6 * time.Second):
		}
		testCtx, stop := context.WithTimeout(ctx, 17*time.Second)
		defer stop()
		results := quickcheck.RunDirect(testCtx, 7*time.Second)
		if ctx.Err() != nil {
			return
		}
		pass := 0
		for _, r := range results {
			if r.Success {
				pass++
			}
		}
		if pass == 0 {
			t.print("TUN direct-route verification failed on both sites; stopping TUN automatically.\n")
			ts.cancel()
		} else {
			t.print("TUN system-route verification: %d/%d sites passed. UDP remains restricted.\n", pass, len(results))
		}
	}()
}
