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
	method, entry, last      string
	starts, running, replies int
	failures, selected       int
	interrupted              int
	updated                  time.Time
}

func (p *wsCarrierProgress) needsTrial() bool { return p.failures == 0 && p.selected == 0 }

type wsTargetProgress struct {
	location  string
	inventory []string
	paths     map[string]*wsCarrierProgress
}

type wsMethodProgress struct {
	name                  string
	total, tried, running int
	last                  string
	updated               time.Time
}

type wsProgressSnapshot struct {
	key, location, carrier                                 string
	total, tried, remaining, interrupted, cooling, running int
	active, connected                                      int
	retryAfter                                             time.Duration
	methods                                                []wsMethodProgress
	incomplete                                             bool
}

func (b *wsBridge) registerCarriers(key, host string, carriers []wsCarrier) {
	var labels []string
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
				p.replies++
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
	rows := make(map[string]*wsMethodProgress)
	now := time.Now()
	for _, name := range target.inventory {
		p := target.paths[name]
		s.total++
		if p.needsTrial() {
			s.remaining++
		} else {
			s.tried++
		}
		s.interrupted += p.interrupted
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
		row.running += p.running
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
	t    *term
	mu   sync.Mutex
	last map[string]time.Time
}

func (v *wsProgressView) show(s wsProgressSnapshot, force bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.last == nil {
		v.last = make(map[string]time.Time)
	}
	if !force && time.Since(v.last[s.key]) < 2*time.Second {
		return
	}
	v.last[s.key] = time.Now()
	title := "WINDSCRIBE " + s.key
	if s.location != "" {
		title += " | " + s.location
	}
	lines := []string{fmt.Sprintf("Variants: %d | tried: %d | still to try: %d | cooling: %d", s.total, s.tried, s.remaining, s.cooling)}
	for _, row := range s.methods {
		lines = append(lines, fmt.Sprintf("%s: %d/%d tried | %s", row.name, row.tried, row.total, row.last))
	}
	k := toneInfo
	switch {
	case s.connected > 0:
		k = toneOK
		lines = append(lines, "VPN: connected (Windscribe CLI). Unused variants remain untested.")
	case s.active > 0:
		lines = append(lines, "VPN: awaiting Windscribe confirmation; a control reply is not VPN success.")
	case s.running > 0:
		lines = append(lines, "VPN: testing transports; no VPN connection confirmed.")
	default:
		lines = append(lines, "VPN: no active confirmed connection.")
	}
	if s.carrier != "" {
		lines = append(lines, "Selected: "+s.carrier)
	}
	switch {
	case s.incomplete:
		lines = append(lines, "More to try: discovery incomplete; WStunnel/Stealth inventory is not yet known.")
	case s.remaining > 0:
		lines = append(lines, fmt.Sprintf("More to try: %d variants. They advance on Windscribe's next connection, not during an established VPN.", s.remaining))
	case s.cooling > 0:
		lines = append(lines, fmt.Sprintf("This pass is exhausted. Retry becomes eligible in %s; this does not prove the IP/country is blocked.", s.retryAfter.Round(time.Second)))
	default:
		lines = append(lines, "All configured variants have been tried; a later retry can still work if the network changes.")
	}
	if s.interrupted > 0 {
		lines = append(lines, "Canceled contenders remain to try; they are not counted as failures.")
	}
	lines = append(lines, "Tried = transport failed or selected for VPN. Only Windscribe confirms the VPN.")
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
			b.view.show(b.progressSnapshot(key), true)
		}
	}
}

func wsProgressHost(key string) string {
	host, _, _ := net.SplitHostPort(key)
	return host
}
