package smartproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAIDomainRulesPrecise(t *testing.T) {
	rules, err := NewAIDomainRules("my-ai.example,=special.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"chatgpt.com", "api.openai.com", "assets.oaistatic.com", "claude.ai", "claude.com", "platform.claude.com", "claudeusercontent.com", "gemini.google.com", "aistudio.google.com", "notebooklm.google.com", "generativelanguage.googleapis.com", "copilot.microsoft.com", "grok.com", "api.my-ai.example", "special.example"} {
		if !rules.Match(name) {
			t.Errorf("should be protected: %s", name)
		}
	}
	for _, name := range []string{"google.com", "youtube.com", "googleapis.com", "microsoft.com", "x.com", "notchatgpt.com", "fakespecial.example", "child.special.example", "fakechatgpt.com", "api.cloudflare.com", "somegemini.google.com", "www.bonbast.com"} {
		if rules.Match(name) {
			t.Errorf("wrong protection: %s", name)
		}
	}
	for _, bad := range []string{"a.example,127.0.0.1", "foo..bar", "a.example,bad/*", "a.example,localhost"} {
		if _, err := NewAIDomainRules(bad); err == nil {
			t.Errorf("accepted invalid AI rule %q", bad)
		}
	}
}

func TestProtectedSNIWinsEvenWhenSOCKSNamesAnOrdinarySite(t *testing.T) {
	rules, _ := NewAIDomainRules("")
	p, _ := New(Config{Upstreams: []Upstream{{Name: "plain"}}, ExitOnly: rules.Match})
	for _, host := range []string{"chatgpt.com", "gemini.google.com", "claude.ai", "claude.com"} {
		flight := capturedClientHello(t, host)
		for _, claimed := range []string{"www.google.com", "188.114.98.0", "10.10.34.36"} {
			if got := p.nameFor(claimed, flight); got != host {
				t.Fatalf("%s hid protected SNI %s: %s", claimed, host, got)
			}
		}
	}
}

func TestFragmentedProtectedClientHelloSendsNoBytesToLocalRoutes(t *testing.T) {
	var hits atomic.Int32
	rules, _ := NewAIDomainRules("")
	p, _ := New(Config{ExitOnly: rules.Match, Upstreams: []Upstream{{Name: "plain", Addr: fakeSocks(t, destination(t), true, &hits)}}})
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Serve(ctx, l)
	f := capturedClientHello(t, "chatgpt.com")
	_, end, _ := sniRange(f)
	parts, err := splitRecords(f, []int{end + 8})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(parts[0], []byte("chatgpt.com")) {
		t.Fatal("test must expose protected SNI in the first record")
	}
	c, err := DialVia(ctx, l.Addr().String(), "www.google.com", "443", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, _ = c.Write(parts[0])
	time.Sleep(20 * time.Millisecond)
	_, _ = c.Write(parts[1])
	_, _ = io.Copy(io.Discard, c)
	if hits.Load() != 0 {
		t.Fatalf("protected SNI escaped on %d local upstream connections", hits.Load())
	}
}

func TestDelayedFirstByteCannotSelectAnISPRouteBeforeSNI(t *testing.T) {
	var hits atomic.Int32
	rules, _ := NewAIDomainRules("")
	p, _ := New(Config{ExitOnly: rules.Match, Upstreams: []Upstream{{Name: "plain", Addr: fakeSocks(t, destination(t), true, &hits)}}})
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Serve(ctx, l)
	f := capturedClientHello(t, "chatgpt.com")
	for _, delay := range []time.Duration{500 * time.Millisecond, 2100 * time.Millisecond} {
		c, err := DialVia(ctx, l.Addr().String(), "188.114.98.0", "443", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		time.Sleep(delay)
		_, _ = c.Write(f)
		_, _ = io.Copy(io.Discard, c)
		c.Close()
		if hits.Load() != 0 {
			t.Fatalf("delayed TLS (%s) escaped on %d ISP routes", delay, hits.Load())
		}
	}
}

func TestForeignOnlyModeCanCarryServerFirstTraffic(t *testing.T) {
	banner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer banner.Close()
	go func() {
		c, err := banner.Accept()
		if err == nil {
			defer c.Close()
			_, _ = c.Write([]byte("SSH-2.0-local-test\r\n"))
		}
	}()
	var hits atomic.Int32
	p, _ := New(Config{ExitOnly: func(string) bool { return true }, Upstreams: []Upstream{{Name: "verified", Exit: true, AIEligible: true, Addr: fakeSocks(t, banner.Addr().String(), true, &hits)}}})
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Serve(ctx, l)
	c, err := DialVia(ctx, l.Addr().String(), "server-first.example", "22", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	b, err := io.ReadAll(c)
	if err != nil || string(b) != "SSH-2.0-local-test\r\n" || hits.Load() != 1 {
		t.Fatalf("server-first foreign route: %q hits=%d err=%v", b, hits.Load(), err)
	}
}

func TestExpiredForeignCheckFailsClosedBeforeAnyAIBytes(t *testing.T) {
	var exitHits, directHits, checks atomic.Int32
	rules, _ := NewAIDomainRules("")
	p, _ := New(Config{ExitOnly: rules.Match, VerifyExit: func(context.Context, Upstream) error { checks.Add(1); return errors.New("location IR or unknown") }, Upstreams: []Upstream{
		{Name: "plain", Addr: fakeSocks(t, destination(t), true, &directHits)},
		{Name: "foreign", Exit: true, AIEligible: true, Addr: fakeSocks(t, destination(t), true, &exitHits)},
	}})
	p.ups[1].verifiedUntil.Store(0)
	for i := 0; i < 2; i++ {
		if _, err := p.race(context.Background(), "chatgpt.com", "443", clientHello()); err == nil {
			t.Fatal("stale/failed geolocation allowed AI")
		}
	}
	if checks.Load() != 1 || exitHits.Load() != 0 || directHits.Load() != 0 {
		t.Fatalf("checks=%d foreign=%d local=%d", checks.Load(), exitHits.Load(), directHits.Load())
	}
	if p.HasVerifiedExit() {
		t.Fatal("expired verification advertised as fresh")
	}
}

func TestConcurrentProtectedDialsShareOneSuccessfulRefresh(t *testing.T) {
	var checks atomic.Int32
	p, _ := New(Config{VerifyExit: func(context.Context, Upstream) error { checks.Add(1); time.Sleep(10 * time.Millisecond); return nil }, Upstreams: []Upstream{{Name: "foreign", Exit: true, AIEligible: true}}})
	u := p.ups[0]
	u.verifiedUntil.Store(0)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.verifyExit(context.Background(), u); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if checks.Load() != 1 || !p.HasVerifiedExit() {
		t.Fatalf("checks=%d verified=%v", checks.Load(), p.HasVerifiedExit())
	}
}

func TestAIRequiresVerifiedExitAndStaysPinned(t *testing.T) {
	rules, _ := NewAIDomainRules("")
	p, err := New(Config{Upstreams: []Upstream{
		{Name: "plain", Rank: 0},
		{Name: "exit unverified", Addr: "127.0.0.1:12555", Exit: true},
		{Name: "verified A", Addr: "127.0.0.1:12556", Exit: true, AIEligible: true, Rank: 5, Late: true},
		{Name: "verified B", Addr: "127.0.0.1:12557", Exit: true, AIEligible: true, Rank: 4, Late: true},
	}, ExitOnly: rules.Match})
	if err != nil {
		t.Fatal(err)
	}
	order := p.order("chatgpt.com", "443")
	if len(order) != 2 {
		t.Fatalf("expected only 2 verified foreign routes, got %d", len(order))
	}
	for _, u := range order {
		if !u.AIEligible || !u.Exit {
			t.Fatalf("unsafe AI upstream: %s", u.Name)
		}
	}
	if len(p.order("example.com", "443")) != 4 {
		t.Fatal("non-AI sites lost their ordinary paths")
	}
	var chosen *upstreamState
	for _, u := range order {
		if u.Name == "verified A" {
			chosen = u
		}
	}
	if chosen == nil {
		t.Fatal("missing verified A")
	}
	p.record(chosen, "chatgpt.com", "443", true, 1)
	for _, name := range []string{"claude.ai", "api.openai.com", "grok.com"} {
		selected := p.order(name, "443")
		if len(selected) != 1 || selected[0].Name != "verified A" {
			t.Fatalf("AI route changed for %s", name)
		}
	}
	p.record(chosen, "chatgpt.com", "443", false, 1)
	if len(p.order("gemini.google.com", "443")) != 1 {
		t.Fatal("failed exit should remain pinned; never silently rotate identity")
	}
}

func TestNoVerifiedAIExitFailsClosed(t *testing.T) {
	rules, _ := NewAIDomainRules("")
	p, err := New(Config{Upstreams: []Upstream{{Name: "plain"}, {Name: "unverified", Addr: "127.0.0.1:10000", Exit: true}}, ExitOnly: rules.Match})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.order("chatgpt.com", "443")) != 0 {
		t.Fatal("AI leaked to direct/unverified route")
	}
	if _, err := p.race(context.Background(), "chatgpt.com", "443", []byte{}); err == nil || !strings.Contains(err.Error(), "fail-closed") {
		t.Fatalf("unexpected error: %v", err)
	}
}
