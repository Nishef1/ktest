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

// switchWriter lets methods built once write to a fresh per-attempt buffer.
type switchWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *switchWriter) set(w io.Writer) {
	s.mu.Lock()
	s.w = w
	s.mu.Unlock()
}

func (s *switchWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	w := s.w
	s.mu.Unlock()
	if w == nil {
		return len(p), nil
	}
	return w.Write(p)
}

// runningCore is one proxy core started by `ktest auto`.
type runningCore struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

func startCore(parent context.Context, m method, dns *dnscheck.Result) (*runningCore, error) {
	if m.err != nil {
		return nil, m.err
	}
	if err := portFree(m.port); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	c := &runningCore{cancel: cancel, done: make(chan struct{})}
	go func() {
		c.err = m.launch(ctx, dns)
		close(c.done)
	}()
	return c, nil
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
	methods := fs.String("methods", "1,2,s", "order to try: 1 Xray B, 2 Xray A, 3 ByeDPI adaptive, 4 ByeDPI TLS slicing, s every ByeDPI strategy in profiles/byedpi-strategies.txt")
	hold := fs.Bool("hold", true, "keep the first working method running until Ctrl+C")
	verbose := fs.Bool("v", false, "show core logs while trying")
	ready := fs.Duration("ready", coreReadyLimit, "how long to wait for each core's local port")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: ktest auto [-methods 1,2,s] [-hold=false] [-v] [-base DIR]")
		return 2
	}
	var tokens []string
	for _, m := range strings.Split(*methods, ",") {
		m = strings.TrimSpace(m)
		if m != "1" && m != "2" && m != "3" && m != "4" && m != "s" {
			fmt.Fprintf(os.Stderr, "unknown method %q; use 1, 2, 3, 4 or s\n", m)
			return 2
		}
		tokens = append(tokens, m)
	}
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	dns := dnscheck.CheckGoogleDNS(ctx)
	fmt.Println("DNS preflight:", dns.Format())

	coreOut := &switchWriter{}
	var order []method
	for _, token := range tokens {
		order = append(order, expandMethod(token, *base, coreOut)...)
	}
	var attempts []autoAttempt
	var best *autoAttempt
	var bestMethod method
	for i, m := range order {
		if ctx.Err() != nil {
			break
		}
		logs := &tailBuffer{max: 4096}
		if *verbose {
			logs.tee = os.Stderr
		}
		// Cores write to the per-attempt buffer so a failure can explain itself.
		coreOut.set(logs)
		core, err := startCore(ctx, m, &dns)
		if err != nil {
			attempts = append(attempts, autoAttempt{label: m.label, note: err.Error()})
			fmt.Printf("SKIP  [%d/%d] %-34s %v\n", i+1, len(order), m.label, err)
			continue
		}
		fmt.Printf("TRY   [%d/%d] %-34s waiting for 127.0.0.1:%d ...\n", i+1, len(order), m.label, m.port)
		if !waitForPort(ctx, core.done, m.port, *ready) {
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
			attempts = append(attempts, autoAttempt{label: m.label, note: note})
			fmt.Printf("FAIL  %-34s %s\n", m.label, note)
			continue
		}
		proxied, compared := measure(ctx, m.port)
		if ctx.Err() != nil {
			core.stop()
			break
		}
		a := autoAttempt{label: m.label, passed: proxiedPassCount(proxied), total: len(proxied)}
		for _, c := range compared {
			fmt.Printf("      %-8s %s\n", c.Target, describeAssessment(c))
		}
		attempts = append(attempts, a)
		if a.full() {
			fmt.Printf("READY %-34s %d/%d targets verified through the proxy\n", m.label, a.passed, a.total)
			return holdCore(ctx, core, m.label, m.port, *hold)
		}
		fmt.Printf("PART  %-34s %d/%d targets verified; trying the next method\n", m.label, a.passed, a.total)
		core.stop()
		if best == nil || a.passed > best.passed {
			cp := a
			best, bestMethod = &cp, m
		}
	}
	if ctx.Err() != nil {
		fmt.Println("Cancelled.")
		return 0
	}
	if best != nil && best.passed > 0 {
		fmt.Printf("\nNo method passed every target; restarting the best partial result: %s (%d/%d).\n", best.label, best.passed, best.total)
		coreOut.set(&tailBuffer{max: 4096})
		core, err := startCore(ctx, bestMethod, &dns)
		if err == nil && waitForPort(ctx, core.done, bestMethod.port, *ready) {
			return holdCore(ctx, core, bestMethod.label, bestMethod.port, *hold)
		}
		if core != nil {
			core.stop()
		}
	}
	fmt.Println("\nNo method could be verified on this network right now:")
	for _, a := range attempts {
		switch {
		case a.note != "":
			fmt.Printf("  - %-34s %s\n", a.label, a.note)
		default:
			fmt.Printf("  - %-34s %d/%d targets\n", a.label, a.passed, a.total)
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
