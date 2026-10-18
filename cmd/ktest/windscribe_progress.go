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
	method, entry, last  string
	failureStage         string
	starts, running      int
	failures, selected   int
	replies, interrupted int
	seq                  uint64
	updated              time.Time
}

func (p *wsCarrierProgress) needsTrial() bool { return p.failures == 0 && p.selected == 0 }

type wsTargetProgress struct {
	location     string
	inventory    []string
	paths        map[string]*wsCarrierProgress
	inapplicable []string
	seq          uint64 // event ordering independent of Windows wall-clock granularity
}

type wsMethodProgress struct {
	name                          string
	total, tried, running, failed int
	started, replied              int
	last                          string
	seq                           uint64
	updated                       time.Time
}

type wsProgressSnapshot struct {
	key, location, carrier                                 string
	currentMethod, recentMethod, recentOutcome             string
	total, tried, remaining, interrupted, cooling, running int
	attempted, failed, replied                             int
	active, connected                                      int
	retryAfter                                             time.Duration
	failStages                                             map[string]int
	methods                                                []wsMethodProgress
	incomplete                                             bool
	mappingReason                                          string
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
				target.seq++
				p.seq = target.seq
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
				p.failureStage = strings.TrimSpace(strings.SplitN(outcome, ":", 2)[0])
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
	s := wsProgressSnapshot{key: key, failStages: make(map[string]int)}
	target := b.targets[key]
	if target == nil {
		return s
	}
	s.location = target.location
	s.inapplicable = append([]string(nil), target.inapplicable...)
	rows := make(map[string]*wsMethodProgress)
	now := time.Now()
	var currentSeq, latestSeq uint64
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
		if p.starts > 0 {
			s.attempted++
		}
		if p.failures > 0 {
			s.failed++
			if p.failureStage != "" {
				s.failStages[p.failureStage]++
			}
		}
		if p.replies > 0 {
			s.replied++
		}
		if p.running > 0 && (s.currentMethod == "" || p.seq > currentSeq) {
			s.currentMethod, currentSeq = p.method, p.seq
		}
		if p.starts > 0 && (s.recentMethod == "" || p.seq > latestSeq) {
			s.recentMethod, s.recentOutcome, latestSeq = p.method, p.last, p.seq
		}
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
		if p.starts > 0 {
			row.started++
		}
		if p.failures > 0 {
			row.failed++
		}
		if p.replies > 0 {
			row.replied++
		}
		if !p.needsTrial() {
			row.tried++
		}
		if row.last == "" || p.seq > row.seq {
			row.last, row.seq, row.updated = p.last, p.seq, p.updated
			if p.starts > 0 {
				row.last += " @ " + p.entry
			}
		}
	}
	for _, row := range rows {
		s.methods = append(s.methods, *row)
	}
	sort.Slice(s.methods, func(i, j int) bool {
		a, b := wsMethodPriority(s.methods[i].name), wsMethodPriority(s.methods[j].name)
		if a != b {
			return a < b
		}
		return s.methods[i].name < s.methods[j].name
	})
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
	s.incomplete = b.opts.direct && b.opts.serverIP == "" && (b.catalog == nil || len(b.catalog.endpoints(wsProgressHost(key))) == 0)
	if s.incomplete {
		if b.catalog == nil {
			s.mappingReason = "catalog disabled"
		} else {
			s.mappingReason = b.catalog.diagnostic(wsProgressHost(key))
		}
	}
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
	t        *term
	verbose  bool
	mu       sync.Mutex
	last     map[string]time.Time
	state    map[string]string
	phase    map[string]string
	panelKey string
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

// These are distinct candidates with an observed failure at each boundary,
// not a claim that the ISP or VPN has blocked that stage.
func wsFailureStages(s wsProgressSnapshot) string {
	var parts []string
	for _, stage := range []string{"tcp", "tls", "websocket", "openvpn"} {
		if count := s.failStages[stage]; count > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", stage, count))
		}
	}
	return strings.Join(parts, " ")
}

func wsShortStatus(s wsProgressSnapshot) string {
	switch {
	case s.connected > 0:
		return "VPN CONNECTED"
	case s.active > 0:
		return "OPENVPN REPLY (unverified)"
	case s.running > 0:
		return "VPN pending"
	case s.incomplete:
		return "discovery incomplete"
	case s.total == 0:
		return "no carriers"
	default:
		return "VPN unconfirmed"
	}
}

// Avoid taking a noisy line off the edge of an 80-column Windows terminal.
func wsShortMethod(name string, maxWidth int) string {
	if maxWidth < 4 {
		return ""
	}
	runes := []rune(name)
	if len(runes) > maxWidth {
		return string(runes[:maxWidth-1]) + "…"
	}
	return name
}

func wsLiveDetail(s wsProgressSnapshot, width int) string {
	status := wsShortStatus(s)
	method := s.currentMethod
	if method == "" {
		method = s.recentMethod
	}
	if width < 60 {
		return fmt.Sprintf("%d/%d checked | %d live | %s", s.tried, s.total, s.running, status)
	}
	if width < 110 {
		phase := "CHECKING"
		switch {
		case s.connected > 0:
			phase = "VPN OK"
		case s.active > 0:
			phase = "OPENVPN?"
		case s.incomplete:
			phase = "DISCOVERY"
		case s.running == 0:
			phase = "IDLE"
		}
		detail := fmt.Sprintf("%d/%d | %d live | %s", s.tried, s.total, s.running, phase)
		if method != "" {
			detail += " | " + wsShortMethod(method, 15)
		}
		return detail
	}
	detail := fmt.Sprintf("%d/%d checked | %d live | %s", s.tried, s.total, s.running, status)
	if method != "" {
		maxMethod := 22
		if width >= 145 {
			maxMethod = 30
		}
		detail += " | " + wsShortMethod(method, maxMethod)
	}
	if width >= 145 {
		if failures := wsFailureStages(s); failures != "" {
			detail += " | failed " + failures
		}
	}
	return detail
}

func wsProgressSignature(s wsProgressSnapshot) string {
	return fmt.Sprintf("%d/%d/%d/%d/%d/%d/%d/%t/%s/%s",
		s.attempted, s.tried, s.remaining, s.running, s.active,
		s.connected, s.failed, s.incomplete, s.carrier, s.currentMethod)
}

func wsProgressPhase(s wsProgressSnapshot) string {
	return fmt.Sprintf("%t/%t/%t/%t/%t", s.connected > 0, s.active > 0,
		s.running > 0, s.incomplete, s.total == 0)
}

// The box lists every method, not every SNI/IP variant. "checked" remains
// distinct from "started"; OpenVPN replies do not imply authenticated VPN.
func wsPanelLines(s wsProgressSnapshot, width int) []string {
	lines := []string{
		fmt.Sprintf("Checked %d/%d  |  Started %d  |  Running %d  |  Left %d", s.tried, s.total, s.attempted, s.running, s.remaining),
		fmt.Sprintf("Transport failures %d  |  Control replies %d  |  Canceled, still to try %d", s.failed, s.replied, s.interrupted),
		"VPN: " + wsShortStatus(s),
	}
	if s.incomplete {
		if s.total == 0 {
			lines = append(lines, "NO WRAPPED CARRIERS: zero tests were run (not 0 failed).")
		}
		lines = append(lines, "Provider mapping discovery incomplete: "+s.mappingReason)
		lines = append(lines, "Exact Windscribe node mapping required; no IP guessing.")
		lines = append(lines, "Retry discovery is automatic; reconnect Windscribe manually after mapping recovers.")
	}
	if s.connected > 0 && s.carrier != "" {
		lines = append(lines, "Confirmed carrier: "+s.carrier)
	} else if s.active > 0 && s.carrier != "" {
		lines = append(lines, "Provisional carrier (awaiting Windscribe): "+s.carrier)
	}
	if stages := wsFailureStages(s); stages != "" {
		lines = append(lines, "Failure stages: "+stages+" (not proof of DPI)")
	}
	if width >= 80 && len(s.methods) > 12 {
		// A 24-row PowerShell window cannot pin a 19-row single-column list.
		// Two columns preserve full method coverage and leave room for logs.
		lines = append(lines, "METHODS: checked/total  -remaining  +running")
		cellWidth := (width - 10) / 2
		nameWidth := max(cellWidth-15, 12)
		half := (len(s.methods) + 1) / 2
		cell := func(m wsMethodProgress) string {
			return fmt.Sprintf("%-*s %2d/%-2d -%-2d +%d",
				nameWidth, wsShortMethod(m.name, nameWidth),
				m.tried, m.total, max(m.total-m.tried, 0), m.running)
		}
		for i := 0; i < half; i++ {
			left := cell(s.methods[i])
			if i+half < len(s.methods) {
				lines = append(lines, fmt.Sprintf("%-*s  %s", cellWidth, left, cell(s.methods[i+half])))
			} else {
				lines = append(lines, left)
			}
		}
	} else {
		if len(s.methods) > 0 {
			lines = append(lines, "Method                                Checked  Left  Active")
		}
		nameWidth := 34
		if width < 70 {
			nameWidth = max(width-37, 10)
		} else if width >= 115 {
			nameWidth = 47
		}
		for _, method := range s.methods {
			pending := max(method.total-method.tried, 0)
			label := wsShortMethod(method.name, nameWidth)
			line := fmt.Sprintf("%-*s %3d/%-3d   %3d    %2d", nameWidth, label,
				method.tried, method.total, pending, method.running)
			if method.replied > 0 {
				line += "  reply"
			} else if method.running > 0 {
				line += "  testing"
			}
			lines = append(lines, line)
		}
	}
	if len(s.inapplicable) > 0 {
		lines = append(lines, fmt.Sprintf("%d IPv6-only methods excluded from this IPv4 target", len(s.inapplicable)))
	}
	lines = append(lines, "Checked = failed or selected; only Windscribe confirms the VPN.")
	lines = append(lines, "Left includes canceled/unselected variants; it is not a failure count.")
	return lines
}

// Updates are owned by the event loop, never by a carrier worker. Interactive
// terminals update one stable boxed panel. Verbose logs remain visible above
// it, while redirected output falls back to occasional complete snapshots.
func (v *wsProgressView) show(s wsProgressSnapshot, force bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.last == nil {
		v.last = make(map[string]time.Time)
		v.state = make(map[string]string)
		v.phase = make(map[string]string)
	}
	signature := wsProgressSignature(s)
	previous, seen := v.state[s.key]
	if seen && previous == signature {
		return
	}
	phase := wsProgressPhase(s)
	urgent := !seen || (v.phase[s.key] != phase &&
		(s.connected > 0 || s.active > 0 || s.incomplete || s.total == 0 ||
			strings.HasPrefix(v.phase[s.key], "true/") ||
			strings.HasPrefix(v.phase[s.key], "false/true/")))
	if seen && !urgent && time.Since(v.last[s.key]) < 3*time.Second {
		return
	}
	v.last[s.key] = time.Now()
	v.state[s.key] = signature
	v.phase[s.key] = phase
	k, _ := wsProgressStatus(s)
	title := "WINDSCRIBE " + s.key
	if s.location != "" {
		title += " | " + s.location
	}
	lines := wsPanelLines(s, v.t.width())
	if v.t.PinBox(title, k, lines) {
		v.panelKey = s.key
		return
	}
	// A short or redirected terminal cannot support a persistent box. Emit
	// full but throttled panels; never produce one box for each quick try.
	v.t.Box(title, k, lines)
}

func (v *wsProgressView) summary(s wsProgressSnapshot) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.t.ClearPinnedBox()
	k, verdict := wsProgressStatus(s)
	title := "WINDSCRIBE " + s.key
	if s.location != "" {
		title += " | " + s.location
	}
	lines := []string{
		fmt.Sprintf("Coverage: %d/%d checked | %d started | %d live | %d remaining", s.tried, s.total, s.attempted, s.running, s.remaining),
		fmt.Sprintf("Evidence: %d failed variants | %d OpenVPN replies | %d cooling | %d interrupted", s.failed, s.replied, s.cooling, s.interrupted),
		"VPN: " + verdict,
	}
	if detail := wsFailureStages(s); detail != "" {
		lines = append(lines, "Failure stages (distinct variants): "+detail)
	}
	if s.carrier != "" {
		lines = append(lines, "Selected: "+s.carrier)
	}
	for _, row := range s.methods {
		lines = append(lines, fmt.Sprintf("%s: %d/%d checked | %d live | %d failed | %d replied | %s",
			row.name, row.tried, row.total, row.running, row.failed, row.replied, row.last))
	}
	if s.incomplete {
		lines = append(lines, "Discovery incomplete: "+s.mappingReason)
		if s.total == 0 {
			lines = append(lines, "No carrier variants were generated or tested; do not treat this as a failed anti-DPI scan.")
		}
	} else if s.remaining > 0 {
		lines = append(lines, fmt.Sprintf("%d untried variants remain for Windscribe's next connection.", s.remaining))
	} else if s.cooling > 0 {
		lines = append(lines, "Recovery cooldown: "+s.retryAfter.Round(time.Second).String())
	}
	if len(s.inapplicable) > 0 {
		lines = append(lines, "Not applicable to IPv4: "+strings.Join(s.inapplicable, "; "))
	}
	lines = append(lines, "Checked = transport failure or selected OpenVPN reply, not VPN success; only Windscribe confirms its VPN.")
	v.t.Box(title, k, lines)
}

// reportProgress runs once at session shutdown, so it preserves past
// CLI-confirmed outcomes even after Windscribe disconnects and active is empty.
func (b *wsBridge) reportProgress() {
	b.mu.Lock()
	keys := make([]string, 0, len(b.targets))
	for key := range b.targets {
		keys = append(keys, key)
	}
	successes := append([]wsConfirmation(nil), b.confirmations...)
	b.mu.Unlock()
	sort.Strings(keys)

	record := wsHistoryRecord{
		Version: 1, StartedAt: b.startedAt, EndedAt: time.Now().UTC(),
		Confirmations: successes,
	}
	for _, key := range keys {
		s := b.progressSnapshot(key)
		if b.view != nil {
			b.view.summary(s)
		}
		target := wsHistoryTarget{Target: key, Location: s.location}
		for _, method := range s.methods {
			m := wsHistoryMethod{
				Name: method.name, VariantsStarted: method.started,
				VariantsChecked: method.tried, VariantsFailed: method.failed,
				OpenVPNReplies: method.replied,
			}
			for _, success := range successes {
				if success.Target == key && success.Method == method.name {
					m.CLIConfirmations++
				}
			}
			target.Methods = append(target.Methods, m)
		}
		record.Targets = append(record.Targets, target)
	}
	if b.view != nil {
		t := b.view.t
		t.Println("")
		if len(successes) == 0 {
			t.Line(toneWarn, "Windscribe: no CLI-correlated VPN connection recorded this session.")
		} else {
			t.Line(toneOK, "Windscribe: %d CLI-correlated VPN %s this session", len(successes), plural(len(successes), "connection", "connections"))
			for i, success := range successes {
				transport, sni, entry, hello := wsCarrierDetails(success.Carrier)
				t.Line(toneOK, "%d. Method: %s | Transport: %s", i+1, success.Method, transport)
				detail := "Target: " + success.Target
				if success.Location != "" {
					detail += " (" + success.Location + ")"
				}
				if sni != "" {
					detail += " | SNI: " + sni
				}
				if entry != "" {
					detail += " | Entry: " + entry
				}
				if hello != "" {
					detail += " | Hello: " + hello
				}
				t.Note("%s", detail)
				t.Note("Carrier: %s", success.Carrier)
			}
		}
		t.Note("Evidence: unique active carrier when Windscribe CLI changed to Connected; socket identity not cryptographically verified.")
	}
	// Persist sessions without successes too: later comparison needs exposure
	// counts, not only a list of apparent winners.
	if b.historyPath != "" {
		if err := appendWSHistory(b.historyPath, record); err != nil {
			if b.view != nil {
				b.view.t.Line(toneWarn, "Windscribe method history not saved: %v", err)
			}
		} else if b.view != nil {
			b.view.t.Note("Method history saved locally: %s", b.historyPath)
		}
	}
}

func wsProgressHost(key string) string {
	host, _, _ := net.SplitHostPort(key)
	return host
}
