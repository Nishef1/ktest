package smartproxy

import (
	"net"
	"sort"
	"strings"
	"time"
)

type routeScore struct {
	wins, fails, failures, earlyFailures int
	ewmaMS                               float64
	coolUntil                            time.Time
}

type destinationMemory struct {
	winner, challenger string
	challengeWins      int
	updated            time.Time
	routes             map[string]*routeScore
}

func destinationKey(host, port string) string {
	return net.JoinHostPort(strings.ToLower(strings.TrimSuffix(host, ".")), port)
}

// A sibling's winner is only an initial hint. It never replaces an exact
// destination's history, failures, latency, or preferred route.
func (p *Proxy) memoryLocked(host, port string) *destinationMemory {
	m := p.mem[destinationKey(host, port)]
	if m != nil && time.Since(m.updated) < p.cfg.MemoryTTL {
		return m
	}
	return nil
}

func (p *Proxy) preferredLocked(host, port string) string {
	if m := p.memoryLocked(host, port); m != nil {
		return m.winner
	}
	if hint, ok := p.hints[destinationKey(siteKey(host), port)]; ok && time.Since(hint.at) < p.cfg.MemoryTTL {
		return hint.name
	}
	return ""
}

func (p *Proxy) order(host, port string) []*upstreamState {
	p.mu.Lock()
	defer p.mu.Unlock()
	var list []*upstreamState
	protected := p.cfg.ExitOnly != nil && p.cfg.ExitOnly(host)
	for _, u := range p.ups {
		if u.Match != nil && !u.Match(host) {
			continue
		}
		if protected && (!u.Exit || !u.AIEligible || (p.aiPinned != "" && u.Name != p.aiPinned)) {
			continue
		}
		list = append(list, u)
	}
	m, preferred := p.memoryLocked(host, port), p.preferredLocked(host, port)
	now := time.Now()
	score := func(u *upstreamState) *routeScore {
		if m != nil {
			return m.routes[u.Name]
		}
		return nil
	}
	cooling := func(u *upstreamState) bool { s := score(u); return s != nil && now.Before(s.coolUntil) }
	rate := func(u *upstreamState) float64 {
		if s := score(u); s != nil {
			return float64(s.wins+1) / float64(s.wins+s.fails+2)
		}
		return .5
	}
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if cooling(a) != cooling(b) {
			return !cooling(a)
		}
		if p.cfg.PreferVerifiedExit && (a.Exit && a.AIEligible) != (b.Exit && b.AIEligible) {
			return a.Exit && a.AIEligible
		}
		if (a.Name == preferred) != (b.Name == preferred) {
			return a.Name == preferred
		}
		if rate(a) != rate(b) {
			return rate(a) > rate(b)
		}
		if a.Rank != b.Rank {
			return a.Rank < b.Rank
		}
		sa, sb := score(a), score(b)
		if sa != nil && sb != nil && sa.ewmaMS != 0 && sb.ewmaMS != 0 {
			return sa.ewmaMS < sb.ewmaMS
		}
		return false
	})
	return list
}

func (p *Proxy) historyLocked(host, port string) *destinationMemory {
	key := destinationKey(host, port)
	m := p.memoryLocked(host, port)
	if m == nil {
		m = &destinationMemory{routes: make(map[string]*routeScore)}
		p.mem[key] = m
	}
	m.updated = time.Now()
	p.historyUpdates++
	if p.historyUpdates%256 == 0 {
		for key, old := range p.mem {
			if time.Since(old.updated) >= p.cfg.MemoryTTL {
				delete(p.mem, key)
			}
		}
		for key, hint := range p.hints {
			if time.Since(hint.at) >= p.cfg.MemoryTTL {
				delete(p.hints, key)
			}
		}
	}
	return m
}

func (m *destinationMemory) score(name string) *routeScore {
	s := m.routes[name]
	if s == nil {
		s = &routeScore{}
		m.routes[name] = s
	}
	return s
}

func (p *Proxy) record(u *upstreamState, host, port string, ok bool, took time.Duration) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	protected := p.cfg.ExitOnly != nil && p.cfg.ExitOnly(host)
	if ok && protected && (!u.Exit || !u.AIEligible || (p.aiPinned != "" && p.aiPinned != u.Name)) {
		return false
	}
	m := p.historyLocked(host, port)
	s := m.score(u.Name)
	if !ok {
		u.fails++
		s.fails++
		s.failures++
		if s.failures >= 2 {
			s.coolUntil = time.Now().Add(30 * time.Second)
			if m.winner == u.Name {
				m.winner = ""
			}
		}
		return true
	}
	u.wins++
	s.wins++
	s.failures = 0
	if p.cfg.ExitOnly != nil && p.cfg.ExitOnly(host) && u.Exit && u.AIEligible && p.aiPinned == "" {
		p.aiPinned = u.Name
		p.logf("Foreign exit pinned for this session: %s", u.Name)
	}
	ms := float64(took) / float64(time.Millisecond)
	if s.ewmaMS == 0 {
		s.ewmaMS = ms
	} else {
		s.ewmaMS = .8*s.ewmaMS + .2*ms
	}
	if u.ewmaMS == 0 {
		u.ewmaMS = ms
	} else {
		u.ewmaMS = .8*u.ewmaMS + .2*ms
	}
	if m.winner == "" || m.winner == u.Name {
		m.winner, m.challenger, m.challengeWins = u.Name, "", 0
	} else {
		if m.challenger != u.Name {
			m.challenger, m.challengeWins = u.Name, 0
		}
		m.challengeWins++
		old := m.routes[m.winner]
		if old == nil || time.Now().Before(old.coolUntil) || (m.challengeWins >= 2 && (old.failures > 0 || old.earlyFailures > 0 || s.ewmaMS < .8*old.ewmaMS)) {
			m.winner, m.challenger, m.challengeWins = u.Name, "", 0
		}
	}
	if m.winner == u.Name && !time.Now().Before(s.coolUntil) {
		p.hints[destinationKey(siteKey(host), port)] = memo{name: u.Name, at: time.Now()}
	}
	return true
}

func (p *Proxy) rememberedName(host, port string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.preferredLocked(host, port)
}

func (p *Proxy) hasMemory(host, port string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.memoryLocked(host, port)
	return m != nil && m.winner != ""
}

// Timing is learned for this exact destination; an unrelated slow site must
// not give a blocked route an excessive head start here.
func (p *Proxy) firstWave(first *upstreamState, host, port string) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	wave := p.cfg.Stagger
	if m := p.memoryLocked(host, port); m != nil {
		if s := m.routes[first.Name]; s != nil {
			wave = max(wave, time.Duration(1.5*s.ewmaMS*float64(time.Millisecond)))
		}
		if m.winner == first.Name {
			wave = max(wave, 4*p.cfg.Stagger)
		}
	}
	return min(wave, 1500*time.Millisecond)
}
