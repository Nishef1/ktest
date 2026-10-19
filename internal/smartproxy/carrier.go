package smartproxy

// LocalCarrierConfig constructs a separate recursion-free transport for
// Aether bootstrap. It shares running local SOCKS cores, never foreign exits,
// imported Xray profiles, takeovers or managed discovery callbacks.
func (p *Proxy) LocalCarrierConfig() Config {
	p.mu.Lock()
	defer p.mu.Unlock()
	rules, _ := NewAIDomainRules("")
	cfg := Config{Stagger: p.cfg.Stagger, MaxParallel: 3, ExitOnly: rules.Match, RejectExits: true, RecoverIPHostSNI: true,
		ConnectTimeout: p.cfg.ConnectTimeout, FirstByteTimeout: p.cfg.FirstByteTimeout, MemoryTTL: p.cfg.MemoryTTL, Logf: p.cfg.Logf}
	for _, u := range p.ups {
		if !u.Exit && u.Takeover == nil && (u.LocalBypass || (u.Addr == "" && u.Dial == nil)) {
			cfg.Upstreams = append(cfg.Upstreams, u.Upstream)
		}
	}
	if p.cfg.HistoryFile != "" && p.cfg.HistoryKey != "" {
		cfg.HistoryFile = p.cfg.HistoryFile + ".carrier"
		cfg.HistoryKey = p.cfg.HistoryKey + "/aether-carrier"
	}
	return cfg
}
