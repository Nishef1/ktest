package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Nishef1/ktest/internal/quickcheck"
	"github.com/Nishef1/ktest/internal/systemtun"
)

// tunnel is the system-wide mode: a Wintun adapter (sing-box) takes every TCP
// connection of every application on this PC and hands it, by host name, to the
// Connect proxy, which carries it over whichever path works. It runs only while
// Connect runs; stopping Connect stops it and Windows restores its routes.
type tunnel struct {
	cancel  context.CancelFunc
	done    chan struct{}
	restore func()
	logs    *tailBuffer
}

// startTunnel brings the tunnel up in front of the proxy on socksPort and
// verifies it with a real system-routed request. If nothing gets through it
// stops again at once, so a failed attempt never leaves the PC without network.
func startTunnel(ctx context.Context, base string, socksPort int, verbose bool, t *term) *tunnel {
	if !systemtun.IsAdmin() {
		t.Line(toneWarn, "The system-wide tunnel needs Administrator; it was not started.")
		t.Note("Use menu 2, or run `ktest connect -tun` (Windows then asks for permission), or open the terminal as Administrator.")
		return nil
	}
	step := t.Progress("Starting the system-wide tunnel", 3)
	nic, dns, err := systemtun.PhysicalNetwork(ctx)
	if err != nil {
		step.Finish(toneFail, err.Error())
		return nil
	}
	step.Set(1, "interface "+nic)
	exe, _ := os.Executable()
	direct := []string{"xray.exe", "ciadpi.exe", "aether.exe", strings.ToLower(filepath.Base(exe))}
	logs := &tailBuffer{max: 4096}
	if verbose {
		logs.tee = os.Stderr
	}
	// The proxy's own name lookups must leave on the real network. Go would
	// otherwise ask the TUN adapter's resolver once Windows prefers it.
	restore := pinSystemDNS(dns)
	tctx, cancel := context.WithCancel(ctx)
	tn := &tunnel{cancel: cancel, done: make(chan struct{}), restore: restore, logs: logs}
	go func() {
		defer close(tn.done)
		err := systemtun.StartSystem(tctx, filepath.Join(base, "cores"), systemtun.Options{
			SocksPort: socksPort, PhysicalNIC: nic, DirectProcesses: direct,
		}, logs)
		if err != nil && tctx.Err() == nil {
			logs.Write([]byte(err.Error() + "\n"))
		}
	}()
	select {
	case <-tn.done:
		step.Finish(toneFail, trimDetail(logs.lastLine()))
		tn.stop(t)
		return nil
	case <-time.After(5 * time.Second):
	case <-ctx.Done():
		tn.stop(t)
		return nil
	}
	step.Set(2, "adapter up")
	vctx, vcancel := context.WithTimeout(ctx, 18*time.Second)
	results := quickcheck.RunDirect(vctx, 7*time.Second)
	vcancel()
	pass := 0
	for _, r := range results {
		if r.Success {
			pass++
		}
	}
	step.Set(3, "")
	if ctx.Err() != nil {
		tn.stop(t)
		return nil
	}
	if pass == 0 {
		step.Finish(toneFail, "no site was reachable through the tunnel; stopped")
		t.Note("Your network is back to normal. Run with -v to see sing-box's output.")
		tn.stop(t)
		return nil
	}
	step.Finish(toneOK, fmt.Sprintf("%d of %d sites reachable through the system route", pass, len(results)))
	return tn
}

// stop ends the tunnel, waits for Windows to get its routes back and restores
// the resolver.
func (tn *tunnel) stop(t *term) {
	if tn == nil {
		return
	}
	tn.cancel()
	select {
	case <-tn.done:
	case <-time.After(12 * time.Second):
		t.Line(toneWarn, "The tunnel did not confirm its shutdown. If the network does not recover, disable and re-enable the adapter.")
	}
	tn.restore()
}

// pinSystemDNS makes this process resolve names through the given servers (the
// real network's own) with Go's resolver, and returns the function that undoes
// it. Names the proxy resolves itself must not depend on what the tunnel does
// to the system resolver.
func pinSystemDNS(servers []string) func() {
	old := net.DefaultResolver
	if len(servers) == 0 {
		return func() {}
	}
	var n atomic.Uint32
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			s := servers[int(n.Add(1))%len(servers)]
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, net.JoinHostPort(s, "53"))
		},
	}
	return func() { net.DefaultResolver = old }
}
