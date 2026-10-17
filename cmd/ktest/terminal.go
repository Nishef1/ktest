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
	wholePC      bool // coverage for policies 1-4; Windscribe owns its own tunnel
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
	{"Connection policy", []menuItem{
		connectItem("1", "Balanced", "everyday access; known AI domains need a verified foreign exit", ModeBalanced),
		connectItem("2", "Fast", "first working route; direct ISP IP or another exit may be used", ModeFast),
		connectItem("3", "VPN exit", "verified foreign exit only; block if unavailable; IP may rotate", ModeVPN),
		connectItem("4", "Tor", "verified Tor exit only; block if unavailable", ModeTor),
		connectItem("5", "Windscribe", "bridge for the Windscribe app; its VPN owns coverage and exit IP", ModeWindscribe),
	}},
	{"Traffic coverage (policies 1-4)", []menuItem{
		{key: "6", name: "Coverage", action: func(t *terminal, _ string, in *input) bool { return t.chooseCoverage(in) }},
	}},
	{"Tools", []menuItem{
		{key: "7", name: "Diagnose", desc: "choose general network or Windscribe checks; reports test limits", action: func(t *terminal, base string, in *input) bool {
			return t.diagnoseMenu(base, in)
		}},
		{key: "8", name: "Setup", action: func(t *terminal, base string, in *input) bool {
			t.setup(base, in.read)
			return true
		}},
		{key: "9", name: "CDN scan", desc: "provider HTTPS reachability or your own Windscribe CDN route", action: func(t *terminal, _ string, in *input) bool {
			return t.cdnScanMenu(in)
		}},
		{key: "10", name: "Windscribe test", desc: "compare SNIs by TCP/TLS/WebSocket; verify a connected VPN separately", action: func(t *terminal, base string, in *input) bool { return t.windscribeTestMenu(base, in) }},
	}},
}

// setupSummary is the Setup line's live description.
func setupSummary(base string) string {
	cert := map[string]string{"ok": "set up", "missing": "off", "outdated": "outdated", "untrusted": "not trusted"}[certState()]
	warp := map[string]string{"ready": "configured (connection unverified)", "no core": "off", "no identity": "not registered"}[warpState(base)]
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
			if it.key == "6" {
				desc = "Proxy apps: configure apps on 10800/10801; change here to Whole PC (TCP)"
				if t.wholePC {
					desc = "Whole PC (TCP): TUN + chosen policy; Administrator; most UDP blocked (change here)"
				}
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
			t.ui.Line(toneWarn, "Unknown option %q. Select 1-10, or 0 to exit.", line)
			continue
		}
		if !it.action(t, base, stdin) {
			return 0
		}
	}
}

func (t *terminal) menuConnectOptions(base string, mode ConnectionMode) connectOptions {
	o := defaultConnectOptions(base)
	o.mode, o.tun = mode, t.wholePC && mode != ModeWindscribe
	o.stopHint = "Press Enter or Ctrl+C to disconnect and return to the menu"
	return o
}

// connectFromMenu offers the certificate first when domain fronting would need
// it, and Administrator for Whole PC. It reports false when stdin closed.
func (t *terminal) connectFromMenu(base string, in *input, mode ConnectionMode) bool {
	o := t.menuConnectOptions(base, mode)
	t.ui.Note("Policy: %s. Coverage: %s", mode, connectionCoverage(o))
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
