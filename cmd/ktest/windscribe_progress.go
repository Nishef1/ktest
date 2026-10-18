package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Coverage belongs to the requested TCP IP:port, not its country, entry IP or
// API hostname. A canceled contender remains available for a real later trial.
type wsCarrierProgress struct {
	method, entry, last string
	starts, running     int
	failures, selected  int
	interrupted         int
	updated             time.Time
}

func (p *wsCarrierProgress) needsTrial() bool { return p.failures == 0 && p.selected == 0 }

type wsTargetProgress struct {
	location     string
	inventory    []string
	paths        map[string]*wsCarrierProgress
	inapplicable []string
}

type wsMethodProgress struct {
	name         string
	total, tried int
	last         string
	updated      time.Time
}

type wsProgressSnapshot struct {
	key, location, carrier                                 string
	total, tried, remaining, interrupted, cooling, running int
	active, connected                                      int
	retryAfter                                             time.Duration
	methods                                                []wsMethodProgress
	incomplete                                             bool
	inapplicable                                           []string
}

func (b *wsBridge) registerCarriers(key, host string, carriers []wsCarrier) {
	var labels []string
	var inapplicable []string
	if b.methods != nil {
		for _, method := range b.methods() {
			if method.IPv6Only {
				inapplicable = append(inapplicable, method.Name)
			}
		}
	}
	if matches := b.catalog.matches(host); len(matches) > 0 {
		for _, label := range []string{matches[0].node.Country, matches[0].node.Group} {
			if label != "" {
				labels = append(labels, label)
			}
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.targets == nil {
		b.targets = make(map[string]*wsTargetProgress)
	}
	target := b.targets[key]
	if target == nil {
		target = &wsTargetProgress{paths: make(map[string]*wsCarrierProgress)}
		b.targets[key] = target
	}
	target.location = strings.Join(labels, " / ")
	target.inapplicable = inapplicable
	target.inventory = nil
	for _, carrier := range carriers {
		target.inventory = append(target.inventory, carrier.name)
		p := target.paths[carrier.name]
		if p == nil {
			p = &wsCarrierProgress{last: "not tried"}
			target.paths[carrier.name] = p
		}
		p.method, p.entry = carrier.method, carrier.addr
		if p.entry == "" {
			p.entry = key
		}
		if p.method == "" {
			p.method = carrier.name
		}
		if p.method == "direct" {
			p.method = "Direct TLS wrapper"
		}
	}
}

func (b *wsBridge) carrierProgress(key, name, outcome string) {
	b.mu.Lock()
	if target := b.targets[key]; target != nil {
		if p := target.paths[name]; p != nil {
			if outcome != "finish" {
				p.updated = time.Now()
			}
			switch outcome {
			case "start":
				p.starts++
				p.running++
				p.last = "testing transport"
			case "finish":
				p.running--
			case "interrupted":
				p.interrupted++
				p.last = "interrupted; still to try"
			case "reply":
				p.last = "OpenVPN reply; VPN unverified"
			default:
				p.failures++
				p.last = outcome
			}
		}
	}
	b.mu.Unlock()
	b.publishProgress(key, false)
}

func (b *wsBridge) progressSnapshot(key string) wsProgressSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := wsProgressSnapshot{key: key}
	target := b.targets[key]
	if target == nil {
		return s
	}
	s.location = target.location
	s.inapplicable = append([]string(nil), target.inapplicable...)
	rows := make(map[string]*wsMethodProgress)
	now := time.Now()
	for _, name := range target.inventory {
		p := target.paths[name]
		s.total++
		if p.needsTrial() {
			s.remaining++
			if p.interrupted > 0 {
				s.interrupted++
			}
		} else {
			s.tried++
		}
		s.running += p.running
		if until := b.bad[key][name]; now.Before(until) {
			s.cooling++
			if wait := until.Sub(now); s.retryAfter == 0 || wait < s.retryAfter {
				s.retryAfter = wait
			}
		}
		row := rows[p.method]
		if row == nil {
			row = &wsMethodProgress{name: p.method}
			rows[p.method] = row
		}
		row.total++
		if !p.needsTrial() {
			row.tried++
		}
		if row.last == "" || p.updated.After(row.updated) {
			row.last, row.updated = p.last, p.updated
			if p.starts > 0 {
				row.last += " @ " + p.entry
			}
		}
	}
	for _, row := range rows {
		s.methods = append(s.methods, *row)
	}
	sort.Slice(s.methods, func(i, j int) bool { return s.methods[i].name < s.methods[j].name })
	for active := range b.active {
		if active.key == key && !active.upstreamEnd {
			s.active++
			if active.confirmed {
				s.connected++
			}
			s.carrier = active.name
			if p := target.paths[active.name]; p != nil {
				for i := range s.methods {
					if s.methods[i].name == p.method {
						s.methods[i].last = "selected; awaiting Windscribe"
						if active.confirmed {
							s.methods[i].last = "connected (Windscribe CLI)"
						}
					}
				}
			}
		}
	}
	// Missing provider mapping is incomplete discovery, not exhausted coverage.
	s.incomplete = b.opts.direct && b.opts.serverIP == "" && len(b.catalog.endpoints(wsProgressHost(key))) == 0
	return s
}

func (b *wsBridge) publishProgress(key string, force bool) {
	if b.onProgress != nil {
		b.onProgress(key, force)
	}
}

type wsProgressEvent struct {
	key   string
	force bool
}

type wsProgressView struct {
	t     *term
	mu    sync.Mutex
	last  map[string]time.Time
	state map[string]string
	line  *progress // one in-place status line for interactive terminals
}

func wsProgressStatus(s wsProgressSnapshot) (tone, string) {
	switch {
	case s.connected > 0:
		return toneOK, "VPN connected (Windscribe CLI)"
	case s.active > 0:
		return toneWarn, "OpenVPN reply; VPN not yet confirmed"
	case s.running > 0:
		return toneInfo, "testing transports; VPN unconfirmed"
	case s.incomplete:
		return toneWarn, "discovery incomplete; carrier list may grow"
	case s.total == 0:
		return toneWarn, "no eligible carrier variants"
	case s.remaining > 0:
		return toneInfo, "awaiting Windscribe's next connection"
	default:
		return toneWarn, "configured variants checked; VPN unconfirmed"
	}
}

// Live updates are a single redrawable status line, not a new 15-row box for
// every carrier event. Redirected output receives an occasional concise row.
// Full per-method diagnostics are emitted once, when the session ends.
func (v *wsProgressView) show(s wsProgressSnapshot, force bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.last == nil {
		v.last = make(map[string]time.Time)
		v.state = make(map[string]string)
	}
	k, verdict := wsProgressStatus(s)
	signature := fmt.Sprintf("%d/%d/%d/%d/%d/%t/%s", s.tried, s.remaining, s.running, s.connected, s.interrupted, s.incomplete, s.carrier)
	previous, seen := v.state[s.key]
	if seen && previous == signature {
		return
	}
	// Avoid flood on back-to-back starts/failures, including forced race
	// notifications. A newly confirmed VPN is reported immediately.
	if seen && s.connected == 0 && time.Since(v.last[s.key]) < 6*time.Second {
		return
	}
	if !force && seen && time.Since(v.last[s.key]) < 2*time.Second {
		return
	}
	v.last[s.key] = time.Now()
	v.state[s.key] = signature
	title := s.key
	if s.location != "" {
		title += " (" + s.location + ")"
	}
	if v.t.live {
		if v.line == nil {
			v.t.Line(toneInfo, "Windscribe carrier search: %s", title)
			v.line = v.t.Progress("Windscribe", max(s.total, 1))
		}
		detail := fmt.Sprintf("%s | %d/%d tried, %d left, %d active | %s", title, s.tried, s.total, s.remaining, s.running, verdict)
		v.line.Set(s.tried, detail)
		if s.connected > 0 {
			v.t.Line(k, "Windscribe confirmed VPN over %s", s.carrier)
		}
		return
	}
	v.t.Line(k, "%s | Windscribe %s | %d/%d tried, %d left, %d running", verdict, title, s.tried, s.total, s.remaining, s.running)
}

func (v *wsProgressView) summary(s wsProgressSnapshot) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.line != nil {
		v.line.Finish(toneInfo, "session ended")
		v.line = nil
	}
	k, verdict := wsProgressStatus(s)
	title := "WINDSCRIBE " + s.key
	if s.location != "" {
		title += " | " + s.location
	}
	lines := []string{
		fmt.Sprintf("Coverage: %d/%d tried | %d remaining | %d interrupted | %d cooling", s.tried, s.total, s.remaining, s.interrupted, s.cooling),
		"VPN: " + verdict,
	}
	if s.carrier != "" {
		lines = append(lines, "Selected: "+s.carrier)
	}
	for _, row := range s.methods {
		lines = append(lines, fmt.Sprintf("%s: %d/%d tried | %s", row.name, row.tried, row.total, row.last))
	}
	if s.incomplete {
		lines = append(lines, "Discovery incomplete; the carrier inventory is not exhaustive.")
	} else if s.remaining > 0 {
		lines = append(lines, fmt.Sprintf("%d untried variants remain for Windscribe's next connection.", s.remaining))
	} else if s.cooling > 0 {
		lines = append(lines, "Recovery cooldown: "+s.retryAfter.Round(time.Second).String())
	}
	if len(s.inapplicable) > 0 {
		lines = append(lines, "Not applicable to IPv4: "+strings.Join(s.inapplicable, "; "))
	}
	lines = append(lines, "A carrier reply is not VPN success. Only Windscribe confirms its VPN.")
	v.t.Box(title, k, lines)
}

func (b *wsBridge) reportProgress() {
	b.mu.Lock()
	var keys []string
	for key := range b.targets {
		keys = append(keys, key)
	}
	b.mu.Unlock()
	sort.Strings(keys)
	for _, key := range keys {
		if b.view != nil {
			b.view.summary(b.progressSnapshot(key))
		}
	}
}

func wsProgressHost(key string) string {
	host, _, _ := net.SplitHostPort(key)
	return host
}
