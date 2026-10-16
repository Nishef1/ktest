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
	out io.Writer
	ui  *term

	mu     sync.Mutex
	cancel context.CancelFunc // the running connection or scan

	certDeclined bool // the user skipped the certificate offer this session
}

func (t *terminal) print(format string, args ...any) { t.ui.Printf(format, args...) }

// menuItem is one line of the main menu.
type menuItem struct {
	key, name, desc string
	mode            ConnectionMode // for connect items
	tun             bool
	action          func(t *terminal, base string, in *input) bool // false: stdin closed
}

func connectItem(key, name, desc string, mode ConnectionMode, tun bool) menuItem {
	return menuItem{key: key, name: name, desc: desc, mode: mode, tun: tun, action: func(t *terminal, base string, in *input) bool {
		return t.connectFromMenu(base, in, tun, mode)
	}}
}

// menuSections is the whole menu: connection modes first, tools after.
var menuSections = []struct {
	title string
	items []menuItem
}{
	{"Connect", []menuItem{
		connectItem("1", "Balanced", "every method races; AI sites only via a foreign exit (recommended)", ModeBalanced, false),
		connectItem("2", "Fast", "fastest working route per site; public IP may change", ModeFast, false),
		connectItem("3", "VPN exit", "one verified foreign exit, pinned for the session", ModeVPN, false),
		connectItem("4", "Tor", "Tor circuit only, never a direct fallback", ModeTor, false),
		connectItem("5", "Windscribe", "carry the Windscribe app over WStunnel + local anti-DPI", ModeWindscribe, false),
		connectItem("6", "Whole PC", "Balanced for every application (Windows, Administrator)", ModeBalanced, true),
	}},
	{"Tools", []menuItem{
		{key: "7", name: "Diagnose", desc: "what this network blocks: DNS, SNI, packet cutting", action: func(t *terminal, base string, _ *input) bool {
			runDoctorView(t.ui, base, false)
			return true
		}},
		{key: "8", name: "Setup", action: func(t *terminal, base string, in *input) bool {
			t.setup(base, in.read)
			return true
		}},
		{key: "9", name: "CDN scan", desc: "find Cloudflare IPs this network reaches (for -windscribe-cdn-edge)", action: func(t *terminal, _ string, _ *input) bool {
			t.foreground(func(ctx context.Context) { runQuickScanContext(ctx, []string{"-provider", "cloudflare"}) })
			return true
		}},
	}},
}

// setupSummary is the Setup line's live description.
func setupSummary(base string) string {
	cert := map[string]string{"ok": "set up", "missing": "off", "outdated": "outdated", "untrusted": "not trusted"}[certState()]
	warp := map[string]string{"ready": "on", "no core": "off", "no identity": "not registered"}[warpState(base)]
	return "certificate: " + cert + " · exit paths (WARP/Psiphon): " + warp
}

func (t *terminal) mainMenu(base string) {
	u := t.ui
	u.Heading("free access toolkit", "")
	for _, s := range menuSections {
		u.Printf("  %s\n", u.Dim(strings.ToUpper(s.title)))
		for _, it := range s.items {
			desc := it.desc
			if it.key == "8" {
				desc = setupSummary(base)
			}
			u.Printf("   %s  %-11s %s\n", u.Bold(u.Cyan(it.key)), u.Bold(it.name), u.Dim(desc))
		}
		u.Println("")
	}
	u.Printf("   %s  %s\n\n  Select > ", u.Bold(u.Cyan("0")), u.Bold("Exit"))
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
	t := &terminal{out: out, ui: newTerm(out)}
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
			lines <- sc.Text()
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
			// Asynchronous output can displace the prompt; Enter just redraws.
			continue
		case "0", "q", "exit":
			return 0
		}
		it, found := findItem(line)
		if !found {
			t.ui.Line(toneWarn, "Unknown option %q. Select 1-9, or 0 to exit.", line)
			continue
		}
		if !it.action(t, base, stdin) {
			return 0
		}
	}
}

// connectFromMenu offers the certificate first when domain fronting would need
// it, and Administrator for Whole PC. It reports false when stdin closed.
func (t *terminal) connectFromMenu(base string, in *input, tun bool, mode ConnectionMode) bool {
	usesFronting := mode == ModeBalanced || mode == ModeFast
	if state := certState(); state != "ok" && !t.certDeclined && usesFronting {
		why := map[string]string{
			"missing":   "Domain fronting (YouTube, X, Instagram, Reddit ...) needs a local certificate that is not set up.",
			"outdated":  "The local certificate predates sites this ktest can front.",
			"untrusted": "The local certificate exists but this system does not trust it yet.",
		}[state]
		t.ui.Line(toneInfo, "%s", why)
		t.print("  Type YES to set it up now (Windows asks you to confirm), or press Enter to skip > ")
		ans, ok := in.read()
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
		relaunchElevated(t.ui, defaultConnectOptions(base))
		return true
	}
	if mode == ModeWindscribe {
		t.ui.Box("WINDSCRIBE SETTINGS", toneInfo, []string{
			t.ui.Bold("Connection  ") + "Protocol OpenVPN TCP, port 443",
			t.ui.Bold("Proxy       ") + "Proxy Settings → HTTP, 127.0.0.1, port 10801, no login",
			t.ui.Dim("Not Proxy Gateway. WireGuard, IKEv2 and Stealth ignore this proxy."),
		})
	}
	o := defaultConnectOptions(base)
	o.mode, o.tun = mode, tun
	o.stopHint = "Press Enter or Ctrl+C to disconnect and return to the menu"
	return t.foreground(func(ctx context.Context) { connectSession(ctx, o, nil, t.ui) }, in.lines)
}
