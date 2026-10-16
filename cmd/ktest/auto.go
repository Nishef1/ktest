package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Nishef1/ktest/internal/dnscheck"
	"github.com/Nishef1/ktest/internal/quickcheck"
)

// tailBuffer keeps only the last bytes a core wrote, so a failed method can
// explain itself without flooding the terminal with every log line.
type tailBuffer struct {
	mu   sync.Mutex
	data []byte
	max  int
	tee  io.Writer
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	b.data = append(b.data, p...)
	if len(b.data) > b.max {
		b.data = b.data[len(b.data)-b.max:]
	}
	tee := b.tee
	b.mu.Unlock()
	if tee != nil {
		_, _ = tee.Write(p)
	}
	return len(p), nil
}

func (b *tailBuffer) lastLine() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	lines := strings.Split(strings.TrimSpace(string(b.data)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// runningCore is one proxy core started by `ktest auto`.
type runningCore struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

func startCore(parent context.Context, choice, base string, dns *dnscheck.Result, out io.Writer) (*runningCore, int, string, error) {
	launch, port, label, err := terminalMode(choice, base, out)
	if err != nil {
		return nil, 0, "", err
	}
	if err := portFree(port); err != nil {
		return nil, 0, label, err
	}
	ctx, cancel := context.WithCancel(parent)
	c := &runningCore{cancel: cancel, done: make(chan struct{})}
	go func() {
		c.err = launch(ctx, dns)
		close(c.done)
	}()
	return c, port, label, nil
}

// stop asks the core to end and waits until its port is released.
func (c *runningCore) stop() bool {
	c.cancel()
	select {
	case <-c.done:
		return true
	case <-time.After(6 * time.Second):
		return false
	}
}

type autoAttempt struct {
	label  string
	passed int
	total  int
	note   string
}

func (a autoAttempt) full() bool { return a.total > 0 && a.passed == a.total }

// runAuto tries each bundled method in turn, verifies it with real HTTPS
// requests through its proxy, and keeps the first one that passes running.
func runAuto(args []string) int {
	fs := flag.NewFlagSet("auto", flag.ContinueOnError)
	exe, _ := os.Executable()
	base := fs.String("base", filepath.Dir(exe), "portable folder holding cores/ and profiles/")
	methods := fs.String("methods", "1,2,3,4", "order to try: 1 Xray B, 2 Xray A, 3 ByeDPI adaptive, 4 ByeDPI TLS slicing")
	hold := fs.Bool("hold", true, "keep the first working method running until Ctrl+C")
	verbose := fs.Bool("v", false, "show core logs while trying")
	ready := fs.Duration("ready", coreReadyLimit, "how long to wait for each core's local port")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: ktest auto [-methods 1,2,3,4] [-hold=false] [-v] [-base DIR]")
		return 2
	}
	var order []string
	for _, m := range strings.Split(*methods, ",") {
		m = strings.TrimSpace(m)
		if m != "1" && m != "2" && m != "3" && m != "4" {
			fmt.Fprintf(os.Stderr, "unknown method %q; use 1, 2, 3 or 4\n", m)
			return 2
		}
		order = append(order, m)
	}
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	dns := dnscheck.CheckGoogleDNS(ctx)
	fmt.Println("DNS preflight:", dns.Format())

	var attempts []autoAttempt
	var best *autoAttempt
	bestChoice := ""
	for _, choice := range order {
		if ctx.Err() != nil {
			break
		}
		logs := &tailBuffer{max: 4096}
		if *verbose {
			logs.tee = os.Stderr
		}
		core, port, label, err := startCore(ctx, choice, *base, &dns, logs)
		if err != nil {
			if label == "" {
				label = "method " + choice
			}
			attempts = append(attempts, autoAttempt{label: label, note: err.Error()})
			fmt.Printf("SKIP  %-26s %v\n", label, err)
			continue
		}
		fmt.Printf("TRY   %-26s waiting for 127.0.0.1:%d ...\n", label, port)
		if !waitForPort(ctx, core.done, port, *ready) {
			note := "proxy port did not open"
			select {
			case <-core.done:
				if core.err != nil {
					note = core.err.Error()
				}
			default:
				if l := logs.lastLine(); l != "" {
					note += "; last core output: " + l
				}
			}
			core.stop()
			if ctx.Err() != nil {
				break
			}
			attempts = append(attempts, autoAttempt{label: label, note: note})
			fmt.Printf("FAIL  %-26s %s\n", label, note)
			continue
		}
		proxied, compared := measure(ctx, port)
		if ctx.Err() != nil {
			core.stop()
			break
		}
		a := autoAttempt{label: label, passed: proxiedPassCount(proxied), total: len(proxied)}
		for _, c := range compared {
			fmt.Printf("      %-8s %s\n", c.Target, describeAssessment(c))
		}
		attempts = append(attempts, a)
		if a.full() {
			fmt.Printf("READY %-26s %d/%d targets verified through the proxy\n", label, a.passed, a.total)
			return holdCore(ctx, core, label, port, *hold)
		}
		fmt.Printf("PART  %-26s %d/%d targets verified; trying the next method\n", label, a.passed, a.total)
		core.stop()
		if best == nil || a.passed > best.passed {
			cp := a
			best, bestChoice = &cp, choice
		}
	}
	if ctx.Err() != nil {
		fmt.Println("Cancelled.")
		return 0
	}
	if best != nil && best.passed > 0 {
		fmt.Printf("\nNo method passed every target; restarting the best partial result: %s (%d/%d).\n", best.label, best.passed, best.total)
		logs := &tailBuffer{max: 4096}
		core, port, label, err := startCore(ctx, bestChoice, *base, &dns, logs)
		if err == nil && waitForPort(ctx, core.done, port, *ready) {
			return holdCore(ctx, core, label, port, *hold)
		}
		if core != nil {
			core.stop()
		}
	}
	fmt.Println("\nNo method could be verified on this network right now:")
	for _, a := range attempts {
		switch {
		case a.note != "":
			fmt.Printf("  - %-26s %s\n", a.label, a.note)
		default:
			fmt.Printf("  - %-26s %d/%d targets\n", a.label, a.passed, a.total)
		}
	}
	fmt.Println("A failed run is evidence, not a reason to retry in a loop. Run `ktest doctor`, check that no other VPN is changing the comparison, or try another access network.")
	return 1
}

func describeAssessment(a quickcheck.Assessment) string {
	switch a.Kind {
	case "candidate":
		return "OK via proxy, blocked directly (bypass candidate; confirm with other VPNs off)"
	case "already_open":
		return "OK via proxy; also reachable directly, so no bypass is attributed"
	case "proxy_regression":
		return "FAILS via proxy but works directly (proxy DNS or routing problem)"
	case "baseline_unknown":
		return "OK via proxy; direct baseline did not finish"
	default:
		return "FAILS via proxy: " + a.Detail
	}
}

func holdCore(ctx context.Context, core *runningCore, label string, port int, hold bool) int {
	fmt.Printf("\n%s is serving 127.0.0.1:%d. Point an application at it explicitly (SOCKS5", label, port)
	if port == xrayPort {
		fmt.Print(" or HTTP")
	}
	fmt.Println("); no system proxy, DNS or route was changed.")
	if !hold {
		core.stop()
		return 0
	}
	fmt.Println("Press Ctrl+C to stop.")
	select {
	case <-ctx.Done():
		core.stop()
		fmt.Println("Stopped.")
		return 0
	case <-core.done:
		fmt.Fprintf(os.Stderr, "%s stopped unexpectedly: %v\n", label, core.err)
		return 1
	}
}
