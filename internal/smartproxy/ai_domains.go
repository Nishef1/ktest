package smartproxy

import (
	"fmt"
	"net"
	"strings"
)

// aiDefaultRules contains known AI entrypoints and their service-specific
// resource domains. Shared domains (google.com, microsoft.com, googleapis.com,
// x.com) are intentionally NOT covered as a whole.
var aiDefaultRules = []string{
	"chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com",
	"claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com",
	"grok.com", "x.ai", "perplexity.ai", "poe.com", "deepseek.com", "deepseek.ai",
	"mistral.ai", "character.ai", "meta.ai", "huggingface.co",
	"stability.ai", "midjourney.com", "runwayml.com", "ideogram.ai",
	"suno.com", "elevenlabs.io", "recraft.ai", "replit.com",
	"cursor.com", "windsurf.com", "bolt.new", "v0.dev", "lovable.dev",
	"=gemini.google.com", "=aistudio.google.com", "=notebooklm.google.com",
	"=generativelanguage.googleapis.com", "=copilot.microsoft.com",
	"=designer.microsoft.com", "=ai.google.dev",
}

// DomainRules matches an exact host, or a parent domain and all its children.
// Prefix '=' selects an exact-only host. No DNS resolution or broad shared-CDN
// address rules are used: those would misroute unrelated sites.
type DomainRules struct {
	suffix []string
	exact  map[string]bool
}

func NewAIDomainRules(extra string) (*DomainRules, error) {
	all := append([]string(nil), aiDefaultRules...)
	for _, token := range strings.Split(extra, ",") {
		if v := strings.TrimSpace(token); v != "" {
			all = append(all, v)
		}
	}
	p := &DomainRules{exact: make(map[string]bool)}
	for _, rule := range all {
		exact := strings.HasPrefix(rule, "=")
		rule = strings.TrimPrefix(strings.TrimSpace(rule), "=")
		host := strings.ToLower(strings.TrimSuffix(rule, "."))
		if !validRuleDomain(host) {
			return nil, fmt.Errorf("invalid AI domain rule: %q", rule)
		}
		if exact {
			p.exact[host] = true
		} else {
			p.suffix = append(p.suffix, host)
		}
	}
	return p, nil
}

func validRuleDomain(host string) bool {
	if net.ParseIP(host) != nil || len(host) < 3 || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	for _, part := range strings.Split(host, ".") {
		if part == "" || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, c := range part {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func (p *DomainRules) Match(name string) bool {
	if p == nil {
		return false
	}
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if p.exact[name] {
		return true
	}
	for _, s := range p.suffix {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}
