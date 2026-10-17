package main

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/Nishef1/ktest/internal/dnscheck"
	"github.com/Nishef1/ktest/internal/systemtun"
)

// launcher runs one proxy core until ctx ends. dns is the preflight the caller
// already measured, so the core does not repeat a multi-second DNS wait.
type launcher func(ctx context.Context, dns *dnscheck.Result) error

// terminal is the interactive menu. Every action runs in the foreground; Enter
// or Ctrl+C ends a connection or scan and returns to the menu.
type terminal struct {
	ui *term

	mu     sync.Mutex
	cancel context.CancelFunc // the running connection or scan

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
		connectItem("1", "Balanced", "Adaptive routing", ModeBalanced),
		connectItem("2", "Fast", "Faster fallback", ModeFast),
		connectItem("3", "Aether", "WARP / Psiphon", ModeAether),
		connectItem("4", "Aether to Tor", "Tor", ModeTor),
		connectItem("5", "Windscribe", "Bridge for the Windscribe app", ModeWindscribe),
		connectItem("6", "Aether to Psiphon", "Psiphon", ModePsiphon),
	}},
	{"Coverage", []menuItem{
		{key: "7", name: "Coverage", action: func(t *terminal, _ string, in *input) bool { return t.chooseCoverage(in) }},
	}},
	{"Tools", []menuItem{
		{key: "8", name: "Diagnose", desc: "Check connection problems", action: func(t *terminal, base string, in *input) bool {
			return t.diagnoseMenu(base, in)
		}},
		{key: "9", name: "Setup", action: func(t *terminal, base string, in *input) bool {
			t.setup(base, in.read)
			return true
		}},
		{key: "10", name: "CDN scan", action: func(t *terminal, _ string, in *input) bool {
			return t.cdnScanMenu(in)
		}},
		{key: "11", name: "Windscribe test", action: func(t *terminal, base string, in *input) bool { return t.windscribeTestMenu(base, in) }},
	}},
}

func policyName(mode ConnectionMode) string {
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
	needsCore := t.options.mode == ModePsiphon || (t.options.mode == ModeAether && t.options.exitSocks == "")
	if needsCore && warpState(base) == "no core" {
		return t.ui.Yellow("Exit core needs setup")
	}
	if (t.options.mode == ModeBalanced || t.options.mode == ModeFast) && !t.options.noFront && !t.settings.SkipCertificateOffer {
		switch certState() {
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
	u.menuView()
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
			if it.mode != "" && it.mode == t.options.mode && t.settings.Connect["mode"] != "" {
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
// swallowing the next menu choice. Ctrl+C on the idle menu closes it.
type input struct {
	lines <-chan string
	quit  <-chan struct{}
}

func (in *input) read() (string, bool) {
	select {
	case l, ok := <-in.lines:
		return strings.TrimSpace(l), ok
	case <-in.quit:
		return "", false
	}
}

// foreground runs job until it ends, Enter is pressed (when lines is not nil)
// or Ctrl+C. It reports false when stdin closed while waiting.
func (t *terminal) foreground(job func(ctx context.Context), lines ...<-chan string) bool {
	ctx, cancel := context.WithCancel(context.Background())
	t.mu.Lock()
	t.cancel = cancel
	t.mu.Unlock()
	done := make(chan struct{})
	go func() { job(ctx); close(done) }()
	alive := true
	var enter <-chan string
	if len(lines) > 0 {
		enter = lines[0]
	}
	select {
	case <-done:
	case _, ok := <-enter:
		alive = ok
	case <-ctx.Done(): // Ctrl+C
	}
	cancel()
	<-done
	t.mu.Lock()
	t.cancel = nil
	t.mu.Unlock()
	return alive
}

// runInteractive is the menu. It never changes Windows routing or DNS itself;
// only Whole PC does, after asking for Administrator.
func runInteractive(in io.Reader, out io.Writer, base string) int {
	settings, path, options, err := loadPreferences(base)
	t := &terminal{ui: newTerm(out), settings: settings, settingsFile: path, options: options}
	defer t.ui.leaveMenu()
	if err != nil {
		t.ui.Line(toneWarn, "Saved settings unavailable; using defaults: %v", err)
	}
	base = options.base
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	quit := make(chan struct{})
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		for {
			select {
			case <-finished:
				return
			case <-interrupts:
				t.mu.Lock()
				cancel := t.cancel
				t.mu.Unlock()
				if cancel != nil {
					cancel() // back to the menu
					continue
				}
				close(quit) // Ctrl+C on the idle menu exits
				return
			}
		}
	}()
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(in)
		for sc.Scan() {
			select {
			case lines <- sc.Text():
			case <-finished:
				return
			}
		}
		close(lines)
	}()
	stdin := &input{lines: lines, quit: quit}

	for {
		t.mainMenu(base)
		line, ok := stdin.read()
		if !ok {
			t.print("\n")
			return 0
		}
		switch strings.ToLower(line) {
		case "":
			t.ui.leaveMenu()
			if !t.connectFromMenu(base, stdin, t.options.mode) {
				return 0
			}
			continue
		case "0", "q", "exit":
			return 0
		}
		it, found := findItem(line)
		if !found {
			t.notice, t.noticeTone = "Unknown option. Use 1-11, Enter, or 0.", toneWarn
			continue
		}
		if it.key != "7" {
			t.ui.leaveMenu()
		}
		if !it.action(t, base, stdin) {
			return 0
		}
	}
}

func (t *terminal) menuConnectOptions(base string, mode ConnectionMode) connectOptions {
	o := optionsForMode(t.options, mode)
	o.base = base
	o.stopHint = "Press Enter or Ctrl+C to disconnect and return to the menu"
	return o
}

// connectFromMenu offers the certificate first when domain fronting would need
// it, and Administrator for Whole PC. It reports false when stdin closed.
func (t *terminal) connectFromMenu(base string, in *input, mode ConnectionMode) bool {
	t.options.mode = mode
	t.rememberConnect("mode", string(mode))
	o := t.menuConnectOptions(base, mode)
	t.ui.Note("Policy: %s. Coverage: %s", mode, connectionCoverage(o))
	usesFronting := (mode == ModeBalanced || mode == ModeFast) && !o.noFront
	if state := certState(); state != "ok" && !t.settings.SkipCertificateOffer && usesFronting {
		why := map[string]string{
			"missing":   "Domain fronting (YouTube, X, Instagram, Reddit ...) needs a local certificate that is not set up.",
			"outdated":  "The local certificate predates sites this ktest can front.",
			"untrusted": "The local certificate exists but this system does not trust it yet.",
		}[state]
		t.ui.Line(toneInfo, "%s", why)
		t.print("  Type YES to set it up now (Windows asks you to confirm), or Enter to skip future offers (Setup remains available) > ")
		ans, ok := in.read()
		if !ok {
			return false
		}
		if strings.EqualFold(ans, "YES") {
			ensureCert(t.ui)
		} else {
			t.settings.SkipCertificateOffer = true
			t.savePreferences()
		}
	}
	if o.tun && !systemtun.IsAdmin() {
		t.ui.Line(toneInfo, "Whole PC needs Administrator.")
		t.print("  Type YES to open an Administrator window (Windows asks you to confirm) > ")
		ans, ok := in.read()
		if !ok {
			return false
		}
		if !strings.EqualFold(ans, "YES") {
			t.ui.Line(toneInfo, "Cancelled.")
			return true
		}
		relaunchElevated(t.ui, o)
		return true
	}
	if mode == ModeWindscribe {
		t.ui.Box("WINDSCRIBE SETTINGS", toneInfo, []string{
			t.ui.Bold("Connection  ") + "Protocol OpenVPN TCP, port 443",
			t.ui.Bold("Proxy       ") + "Proxy Settings → HTTP, 127.0.0.1, port 10801, no login",
			t.ui.Dim("Not Proxy Gateway. WireGuard, IKEv2 and Stealth ignore this proxy."),
		})
	}
	return t.foreground(func(ctx context.Context) { connectSession(ctx, o, nil, t.ui) }, in.lines)
}
