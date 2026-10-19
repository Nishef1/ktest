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
	rejected                             bool
	kind                                 FailureKind // why this route last failed here
}

type destinationMemory struct {
	winner, challenger string
	challengeWins      int
	updated            time.Time
	routes             map[string]*routeScore
	// kind is the filtering this destination showed (the plain route's
	// failure when known); failed lists families that failed here and
	// credited the family last credited to the network priors.
	kind         FailureKind
	failed       map[string]bool
	lossCredited map[string]bool
	credited     string
}

func destinationKey(host, port string) string {
	return net.JoinHostPort(strings.ToLower(strings.TrimSuffix(host, ".")), port)
}

// A sibling's winner is only an initial hint. It never replaces an exact
// destination's history, failures, latency, or preferred route.
func (p *Proxy) memoryLocked(host, port string) *destinationMemory {
	m := p.mem[destinationKey(host, port)]
	if m == nil {
		key := historyDestination(host, port)
		if saved, ok := p.saved[key]; ok {
			delete(p.saved, key)
			if time.Since(saved.Updated) < p.cfg.MemoryTTL && time.Until(saved.Updated) < time.Minute {
				m = &destinationMemory{winner: saved.Winner, updated: saved.Updated, routes: map[string]*routeScore{},
					kind: kindFromKey(saved.Kind), credited: saved.Credited}
				for name, s := range saved.Routes {
					m.routes[name] = &routeScore{wins: s.Wins, fails: s.Fails, ewmaMS: s.LatencyMS, kind: kindFromKey(s.Kind)}
				}
				p.mem[destinationKey(host, port)] = m
			}
		}
	}
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
	m := p.memoryLocked(host, port)
	literal := net.ParseIP(host)
	for _, u := range p.ups {
		if u.Match != nil && !u.Match(host) {
			continue
		}
		// An IP literal can only be dialed in its own family.
		if literal != nil && u.Addr == "" &&
			((u.Network == "tcp6" && literal.To4() != nil) || (u.Network == "tcp4" && literal.To4() == nil)) {
			continue
		}
		if protected && (!u.Exit || !u.AIEligible || (p.aiPinned != "" && u.Name != p.aiPinned)) {
			continue
		}
		if m != nil && u.Takeover != nil {
			if s := m.routes[u.Name]; s != nil && s.rejected {
				continue
			}
		}
		list = append(list, u)
	}
	if pins := p.cfg.Frozen; pins != nil {
		selected, pinned := pins.Default, !pins.Adaptive
		if protected {
			selected, pinned = pins.Protected, true
		} else if method, ok := pins.Targets[destinationKey(host, port)]; ok {
			selected, pinned = method, !pins.Adaptive || method != ""
		}
		if pinned {
			for _, u := range list {
				if selected != "" && u.Name == selected {
					return []*upstreamState{u}
				}
			}
			return nil
		}
	}
	preferred := p.preferredLocked(host, port)
	// A destination that already showed a kind of filtering but has no
	// winner of its own starts with the family this network taught.
	var priorFamily string
	if m != nil && m.winner == "" && p.priorsApplyLocked(host) {
		priorFamily = p.priors[m.kind].best()
	}
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
		if priorFamily != "" && (a.family == priorFamily) != (b.family == priorFamily) {
			return a.family == priorFamily
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
	kind := KindNone
	if !ok {
		kind = KindOther
	}
	return p.recordOutcome(u, host, port, kind, took)
}

// recordFailure scores a failed attempt with the kind its error carries.
func (p *Proxy) recordFailure(u *upstreamState, host, port string, err error, took time.Duration) FailureKind {
	kind := failureKind(err)
	if kind == KindNone {
		kind = KindOther
	}
	p.recordOutcome(u, host, port, kind, took)
	return kind
}

// recordOutcome scores one attempt: KindNone is a success, anything else a
// failure of that kind.
func (p *Proxy) recordOutcome(u *upstreamState, host, port string, kind FailureKind, took time.Duration) bool {
	ok := kind == KindNone
	p.mu.Lock()
	defer p.mu.Unlock()
	protected := p.cfg.ExitOnly != nil && p.cfg.ExitOnly(host)
	if ok && protected && (!u.Exit || !u.AIEligible || (p.aiPinned != "" && p.aiPinned != u.Name)) {
		return false
	}
	m := p.historyLocked(host, port)
	s := m.score(u.Name)
	if ok && u.Takeover != nil && s.rejected {
		return false // another connection's preparation cannot undo a client refusal
	}
	if !ok {
		u.fails++
		s.fails++
		s.failures++
		if kind.informative() {
			s.kind = kind
		}
		p.noteFailureLocked(m, u, host, kind)
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
	p.creditLocked(m, u, host)
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

// A client refusal makes this takeover ineligible while the exact destination's
// history is live. A cooldown alone would still let it win a fallback hedge
// before a slower end-to-end route. Never replay bytes after takeover has begun.
func (p *Proxy) rejectTakeover(host, port, path string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.historyLocked(host, port)
	s := m.score(path)
	s.fails++
	s.rejected = true
	s.kind = KindBlockPage // the client refused the certificate presented
	if m.winner == path {
		m.winner = ""
	}
	for _, u := range p.ups {
		if u.Name == path {
			u.fails++
			break
		}
	}
}

// The configured stagger is a hedge budget, not a reward for a slow winner.
// Fast learned routes get a shorter head start; slow ones never delay the
// alternatives beyond the configured budget.
func (p *Proxy) firstWave(first *upstreamState, host, port string) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	wave := p.cfg.Stagger
	if m := p.memoryLocked(host, port); m != nil {
		if s := m.routes[first.Name]; s != nil {
			if s.ewmaMS > 0 {
				wave = min(wave, max(50*time.Millisecond, time.Duration(1.5*s.ewmaMS*float64(time.Millisecond))))
			}
		}
	}
	return min(wave, 1500*time.Millisecond)
}
