package smartproxy

import (
	"context"
	"strings"
	"testing"
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
