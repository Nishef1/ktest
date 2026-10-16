package smartproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/httpproxy"
)

func TestWindscribeRetriesRotatePerDestinationAfterTCPAcceptsButDropsData(t *testing.T) {
	var hits [3]atomic.Int32
	dest := destination(t)
	events := make(chan Event, 18)
	p, err := New(Config{LocalOnly: true, RejectExits: true, OnEvent: func(e Event) { events <- e }, Upstreams: []Upstream{
		{Name: "drops data 1", Addr: fakeSocks(t, dest, false, &hits[0]), LocalBypass: true},
		{Name: "drops data 2", Addr: fakeSocks(t, dest, false, &hits[1]), LocalBypass: true},
		{Name: "answers", Addr: fakeSocks(t, dest, true, &hits[2]), LocalBypass: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- (&httpproxy.Server{Upstream: p.cfg.Upstreams[0].Addr, Dial: p.DialWindscribeLocal}).Serve(ctx, listener)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	connect := func(host, port string) net.Conn {
		t.Helper()
		c, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		target := net.JoinHostPort(host, port)
		_, _ = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		r := bufio.NewReader(c)
		status, err := r.ReadString('\n')
		if err != nil || !strings.Contains(status, " 200 ") {
			_ = c.Close()
			t.Fatalf("CONNECT: %q, %v", status, err)
		}
		if line, err := r.ReadString('\n'); err != nil || line != "\r\n" {
			_ = c.Close()
			t.Fatalf("CONNECT headers: %q, %v", line, err)
		}
		return c
	}
	for attempt := 0; attempt < 6; attempt++ {
		// Incidental API traffic must neither select the VPN's strategy nor
		// advance its retry sequence, even when it uses the same IP on a different port.
		for _, target := range [][2]string{{"api.windscribe.com", "443"}, {"198.51.100.23", "80"}} {
			c := connect(target[0], target[1])
			_ = c.Close()
		}
		c := connect("198.51.100.23", "443")
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_, writeErr := c.Write([]byte("opaque VPN first flight"))
		answer := make([]byte, len(serverHello))
		_, readErr := io.ReadFull(c, answer)
		_ = c.Close()
		if attempt%3 == 2 {
			if writeErr != nil || readErr != nil || !bytes.Equal(answer, serverHello) {
				t.Fatalf("retry %d did not reach answering path: write=%v read=%v answer=%x", attempt, writeErr, readErr, answer)
			}
		} else if readErr == nil {
			t.Fatalf("retry %d should reproduce an accepted TCP socket that drops data", attempt)
		}
	}
	for i := range hits {
		if got := hits[i].Load(); got != 6 {
			t.Fatalf("path %d used %d times, want 6 (two attempts per destination)", i, got)
		}
	}
	for _, stat := range p.Stats() {
		if stat.Wins != 0 {
			t.Fatalf("TCP acceptance was counted as a verified answer: %+v", stat)
		}
	}
	for i := 0; i < 18; i++ {
		e := <-events
		if !e.TCPOnly || e.OK {
			t.Fatalf("TCP accepted without an application answer must remain unverified: %+v", e)
		}
	}
}

func TestWindscribeTCPFailureFallsBackOnlyToLocalMethod(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := closed.Addr().String()
	_ = closed.Close()
	var hits atomic.Int32
	p, err := New(Config{Upstreams: []Upstream{
		{Name: "plain", Rank: -2},
		{Name: "foreign", Exit: true, AIEligible: true, Addr: dead, Rank: -1},
		{Name: "dead local", LocalBypass: true, Addr: dead},
		{Name: "answering local", LocalBypass: true, Addr: fakeSocks(t, destination(t), true, &hits)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := p.DialWindscribeLocal(ctx, "198.51.100.23", "443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, _ = c.Write([]byte("opaque VPN first flight"))
	answer := make([]byte, len(serverHello))
	if _, err := io.ReadFull(c, answer); err != nil || !bytes.Equal(answer, serverHello) {
		t.Fatalf("local fallback did not carry data: answer=%x err=%v", answer, err)
	}
	if hits.Load() != 1 {
		t.Fatal("did not use the local method")
	}
}

func TestWindscribeConcurrentRetriesDoNotInterruptOpenStreams(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	var hits [3]atomic.Int32
	var ups []Upstream
	for i, name := range []string{"one", "two", "three"} {
		ups = append(ups, Upstream{Name: name, LocalBypass: true, Addr: fakeSocks(t, l.Addr().String(), true, &hits[i])})
	}
	p, err := New(Config{LocalOnly: true, RejectExits: true, Upstreams: ups})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	held, err := p.DialWindscribeLocal(ctx, "198.51.100.23", "443")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := p.DialWindscribeLocal(ctx, "198.51.100.23", "443")
			if err != nil {
				t.Error(err)
				return
			}
			_ = c.Close()
		}()
	}
	wg.Wait()
	for i := range hits {
		if hits[i].Load() != 3 {
			t.Fatalf("simultaneous retries did not cycle all paths: path %d used %d times", i, hits[i].Load())
		}
	}
	_ = held.SetDeadline(time.Now().Add(time.Second))
	flight := []byte("still the original stream")
	if _, err := held.Write(flight); err != nil {
		t.Fatal(err)
	}
	answer := make([]byte, len(flight))
	if _, err := io.ReadFull(held, answer); err != nil || !bytes.Equal(answer, flight) {
		t.Fatalf("new attempts interrupted existing stream: %q, %v", answer, err)
	}
}

func TestWindscribeLocalOnlyRejectsForeignExits(t *testing.T) {
	if _, err := New(Config{
		RejectExits: true,
		LocalOnly:   true,
		Upstreams:   []Upstream{{Name: "foreign", Exit: true, Addr: "127.0.0.1:10002"}},
	}); err == nil {
		t.Fatal("started foreign exit in Windscribe local-only mode")
	}
	p, err := New(Config{RejectExits: true, LocalOnly: true, Upstreams: []Upstream{
		{Name: "packet cutter", Send: func(net.Conn, []byte) error { return nil }},
		{Name: "local ByeDPI", Addr: "127.0.0.1:12001", LocalBypass: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Add(Upstream{Name: "Aether", Exit: true, Addr: "127.0.0.1:12002"}); err == nil {
		t.Fatal("dynamically added forbidden foreign exit")
	}
	if err := p.Add(Upstream{Name: "plain", Rank: 0}); err == nil {
		t.Fatal("dynamic plain connection bypassed local-only policy")
	}
	if err := p.Add(Upstream{Name: "unknown relay", Addr: "127.0.0.1:22002"}); err == nil {
		t.Fatal("dynamic unverified SOCKS relay bypassed local-only policy")
	}
	if p.HasVerifiedExit() {
		t.Fatal("foreign exit was registered")
	}
	if !p.HasLocalBypass() {
		t.Fatal("local ByeDPI disappeared")
	}
	if len(p.Stats()) != 2 {
		t.Fatalf("unexpected upstream count %d", len(p.Stats()))
	}
}

func TestWindscribeLocalBootstrapNeverSelectsDirectOrForeign(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	targets := make(chan string, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				buf := make([]byte, 3)
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				if _, err := c.Write([]byte{5, 0}); err != nil {
					return
				}
				hdr := make([]byte, 4)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				if hdr[3] != 1 {
					return
				}
				a := make([]byte, 6)
				if _, err := io.ReadFull(c, a); err != nil {
					return
				}
				targets <- net.IP(a[:4]).String()
				if binary.BigEndian.Uint16(a[4:]) != 443 {
					return
				}
				_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	defer func() { _ = l.Close(); <-done }()
	p, err := New(Config{Upstreams: []Upstream{
		{Name: "direct", Rank: 0},
		{Name: "unverified foreign", Exit: true, Addr: "127.0.0.1:19999", Rank: 1},
		{Name: "local ByeDPI", LocalBypass: true, Addr: l.Addr().String(), Rank: 3},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c, err := p.DialWindscribeLocal(ctx, "198.51.100.23", "443")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	select {
	case h := <-targets:
		if h != "198.51.100.23" {
			t.Fatal(h)
		}
	case <-time.After(time.Second):
		t.Fatal("local SOCKS did not get target")
	}
	p.mu.Lock()
	pin := p.bootstrapPinned
	p.mu.Unlock()
	if pin != "" {
		t.Fatalf("TCP acceptance must not pin a Windscribe session: %q", pin)
	}
}

func TestWindscribeNoLocalBypassReturnsErrorWithoutDial(t *testing.T) {
	p, err := New(Config{Upstreams: []Upstream{
		{Name: "direct", Rank: 0},
		{Name: "external SOCKS", Addr: "127.0.0.1:20003", Exit: true, AIEligible: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := p.DialWindscribeLocal(ctx, "198.51.100.23", "443")
	if c != nil {
		c.Close()
		t.Fatal("unsafe route")
	}
	if err == nil || !strings.Contains(err.Error(), "no local IP-preserving") {
		t.Fatalf("wrong error %v", err)
	}
}

func TestWindscribeLocalOnlyRejectsPlainAndUnknownProxiesAtStartup(t *testing.T) {
	for _, u := range []Upstream{
		{Name: "plain", Addr: ""},
		{Name: "plain fake label", Addr: "127.0.0.1:22001"},
		{Name: "untrusted remote", Addr: "198.51.100.4:22002", LocalBypass: true},
		{Name: "front takeover", Takeover: func(context.Context, string, string, []byte) (Session, error) { return nil, nil }},
	} {
		if _, err := New(Config{LocalOnly: true, RejectExits: true, Upstreams: []Upstream{u}}); err == nil {
			t.Fatalf("unsafe upstream %q accepted", u.Name)
		}
	}
}
