package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/smartproxy"
)

func TestWindscribeCoverageKeepsCanceledAndReplyOnlyVariantsAvailable(t *testing.T) {
	b := testBridge(&dialLog{})
	key := "203.0.113.100:443"
	cs := []wsCarrier{{name: "failed", method: "ByeDPI"}, {name: "canceled", method: "ByeDPI"}, {name: "reply only", method: "WStunnel"}}
	b.registerCarriers(key, "203.0.113.100", cs)
	for _, name := range []string{"failed", "canceled", "reply only"} {
		b.carrierProgress(key, name, "start")
	}
	b.carrierProgress(key, "failed", "tls: reset")
	b.carrierProgress(key, "canceled", "interrupted")
	b.carrierProgress(key, "reply only", "reply")
	for _, name := range []string{"failed", "canceled", "reply only"} {
		b.carrierProgress(key, name, "finish")
	}
	s := b.progressSnapshot(key)
	if s.total != 3 || s.tried != 1 || s.remaining != 2 || s.interrupted != 1 || s.running != 0 || s.connected != 0 {
		t.Fatalf("canceled/reply-only paths were counted as tested VPNs: %+v", s)
	}
	order := b.ordered(key, cs)
	if order[len(order)-1].name != "failed" {
		t.Fatal("untested variants did not precede previously checked failures")
	}
	other := "203.0.113.200:443"
	b.registerCarriers(other, "203.0.113.200", cs)
	if fresh := b.progressSnapshot(other); fresh.tried != 0 || fresh.remaining != 3 {
		t.Fatal("one IP inherited another IP's coverage")
	}
}

func TestWindscribeProviderGroupLabelsFollowProviderHierarchy(t *testing.T) {
	b := testBridge(&dialLog{})
	b.catalog = newWSNodeCatalog()
	body := []byte(`{"data":[{"name":"Sweden","groups":[{"city":"Stockholm","nick":"Fika","nodes":[{"ip":"198.51.100.10","ip2":"203.0.113.100","ip3":"192.0.2.10","hostname":"se.example.com"}]}]}]}`)
	if err := b.catalog.replace("global", body, time.Now()); err != nil {
		t.Fatal(err)
	}
	b.registerCarriers("203.0.113.100:443", "203.0.113.100", []wsCarrier{{name: "one"}})
	s := b.progressSnapshot("203.0.113.100:443")
	if s.location != "Sweden / Stockholm - Fika" {
		t.Fatalf("provider grouping lost: %q", s.location)
	}
}

func TestWindscribeCatalogGapNeverReportsExhaustedCoverage(t *testing.T) {
	b := testBridge(&dialLog{})
	b.opts.direct = true
	b.registerCarriers("203.0.113.100:1194", "203.0.113.100", []wsCarrier{{name: "raw"}})
	b.carrierProgress("203.0.113.100:1194", "raw", "tcp: failed")
	s := b.progressSnapshot("203.0.113.100:1194")
	if !s.incomplete {
		t.Fatal("missing mapping was mistaken for a complete method inventory")
	}
	var out bytes.Buffer
	(&wsProgressView{t: plainTerm(&out)}).show(s, true)
	if strings.Contains(out.String(), "pass is exhausted") || !strings.Contains(out.String(), "discovery incomplete") {
		t.Fatalf("misleading report with an unknown provider node: %s", out.String())
	}
}

func TestWindscribeInventoryNamesEveryMethodAndExcludesRawVPN(t *testing.T) {
	b := newWSBridge(wsOptions{direct: true, sni: "example.com", serverIP: "198.51.100.10"}, nil, nil, func(string, ...any) {})
	b.methods = func() []smartproxy.WindscribeMethod {
		return []smartproxy.WindscribeMethod{{Name: "ByeDPI A"}, {Name: "ByeDPI B"}, {Name: "TLS cut", TLSOnly: true}, {Name: "IPv6 cut", TLSOnly: true, IPv6Only: true}}
	}
	seen := make(map[string]int)
	for _, c := range b.carriersFor("203.0.113.100") {
		seen[c.method]++
		if strings.HasPrefix(c.name, "raw OpenVPN") {
			t.Fatalf("raw OpenVPN should never be queued: %+v", c)
		}
	}
	for _, method := range []string{"direct", "ByeDPI A", "ByeDPI B", "TLS cut"} {
		if seen[method] == 0 {
			t.Fatalf("method hidden from coverage: %s", method)
		}
	}
	b.registerCarriers("203.0.113.100:443", "203.0.113.100", b.carriersFor("203.0.113.100"))
	s := b.progressSnapshot("203.0.113.100:443")
	if seen["IPv6 cut"] != 0 || len(s.inapplicable) != 1 || s.inapplicable[0] != "IPv6 cut" {
		t.Fatal("IPv6 incompatibility was hidden or counted as an IPv4 trial")
	}
}

func TestWindscribeProgressPanelsFitTerminalAndKeepTargetsSeparate(t *testing.T) {
	for _, width := range []int{40, 80, 120} {
		var out bytes.Buffer
		v := &wsProgressView{t: &term{w: &out, columns: width}}
		v.show(wsProgressSnapshot{key: "68.67.118.163:443", location: "Sweden / Stockholm - Fika", total: 4, tried: 1, remaining: 3,
			methods: []wsMethodProgress{{name: "ByeDPI split", total: 4, tried: 1, last: "openvpn: reset"}}}, true)
		v.show(wsProgressSnapshot{key: "23.189.168.163:443", location: "US / South Bend - Hawkins", total: 2, tried: 1, remaining: 1, active: 1, connected: 1}, true)
		for _, line := range strings.Split(out.String(), "\n") {
			if visibleLen(line) > width {
				t.Fatalf("report overflows width %d: %q", width, line)
			}
		}
		if !strings.Contains(out.String(), "68.67.118.163:443") || !strings.Contains(out.String(), "23.189.168.163:443") {
			t.Fatal("target identity missing")
		}
		if width == 120 {
			t.Log("Rendered target panels:\n" + out.String())
		}
	}
}

func TestWindscribeCoverageFollowsRealCarrierLifecycle(t *testing.T) {
	b := testBridge(&dialLog{}, carrierSpec{name: "WStunnel test"})
	conn, done, err := b.race(context.Background(), "203.0.113.100", "443", openvpnReset, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	s := b.progressSnapshot("203.0.113.100:443")
	if s.tried != 1 || s.active != 1 || s.connected != 0 {
		t.Fatalf("control reply credited with VPN success: %+v", s)
	}
	b.observeCLIConnected()
	if s = b.progressSnapshot(s.key); s.connected != 1 {
		t.Fatal("CLI confirmation not reflected in its target group")
	}
	done(time.Second, 1024)
	if s = b.progressSnapshot(s.key); s.active != 0 || s.connected != 0 {
		t.Fatal("ended session still shown as connected")
	}
}

func TestWindscribeProgressRenderingNeverRunsInsideCarrierWorkers(t *testing.T) {
	b := testBridge(&dialLog{}, carrierSpec{name: "WStunnel test"})
	var out bytes.Buffer
	b.view = &wsProgressView{t: plainTerm(&out)}
	notifications := make(chan wsProgressEvent, 1)
	b.onProgress = func(key string, force bool) {
		select {
		case notifications <- wsProgressEvent{key: key, force: force}:
		default:
		}
	}
	conn, done, err := b.race(context.Background(), "203.0.113.100", "443", openvpnReset, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done(time.Second, 1024)
	if out.Len() != 0 {
		t.Fatal("carrier worker wrote to a potentially blocking terminal")
	}
	s := b.progressSnapshot("203.0.113.100:443")
	if s.tried != 1 || s.remaining != 0 {
		t.Fatal("a full notification queue lost underlying coverage")
	}
	b.view.show(s, true)
	if out.Len() == 0 {
		t.Fatal("queued progress could not be rendered by the live feed")
	}
}

func TestWindscribeCompactProgressDeduplicatesForcedEvents(t *testing.T) {
	var out bytes.Buffer
	v := &wsProgressView{t: plainTerm(&out)}
	snapshot := wsProgressSnapshot{key: "203.0.113.100:443", total: 281, tried: 0, remaining: 281}
	for i := 0; i < 20; i++ {
		v.show(snapshot, true)
	}
	if got := strings.Count(out.String(), "WINDSCRIBE 203.0.113.100:443"); got != 1 {
		t.Fatalf("unchanged events generated %d duplicate boxes:\n%s", got, out.String())
	}
}

func TestWindscribeSummaryRetainsFullMethodDetails(t *testing.T) {
	var out bytes.Buffer
	v := &wsProgressView{t: plainTerm(&out)}
	snapshot := wsProgressSnapshot{
		key: "203.0.113.100:443", total: 2, tried: 1, remaining: 1,
		methods:      []wsMethodProgress{{name: "ByeDPI", tried: 1, total: 2, last: "TLS reset"}},
		inapplicable: []string{"IPv6-only"},
	}
	v.show(snapshot, true)
	if strings.Contains(out.String(), "TLS reset") {
		t.Fatal("live feed printed the full method table")
	}
	v.summary(snapshot)
	if !strings.Contains(out.String(), "ByeDPI: 1/2 checked | 0 live | 0 failed | 0 replied | TLS reset") || !strings.Contains(out.String(), "Not applicable to IPv4") {
		t.Fatalf("final summary lost diagnostic detail: %s", out.String())
	}
}

func TestWindscribeSnapshotDistinguishesStartedCheckedAndReplies(t *testing.T) {
	b := testBridge(&dialLog{})
	key := "203.0.113.100:443"
	b.registerCarriers(key, "203.0.113.100", []wsCarrier{
		{name: "one", method: "TLS slicing"},
		{name: "two", method: "TLS slicing"},
		{name: "three", method: "Xray"},
	})
	b.carrierProgress(key, "one", "start")
	b.carrierProgress(key, "two", "start")
	b.carrierProgress(key, "two", "tls: reset by peer")
	b.carrierProgress(key, "two", "finish")
	b.carrierProgress(key, "three", "start")
	b.carrierProgress(key, "three", "reply")
	// Windows timer granularity can assign identical wall-clock timestamps
	// to all three events. Sequence numbers must retain their real order.
	b.mu.Lock()
	for _, p := range b.targets[key].paths {
		p.updated = time.Unix(0, 0)
	}
	b.mu.Unlock()
	s := b.progressSnapshot(key)
	if s.attempted != 3 || s.tried != 1 || s.remaining != 2 || s.running != 2 {
		t.Fatalf("started variants or live transports were conflated with checked results: %+v", s)
	}
	if s.failed != 1 || s.failStages["tls"] != 1 || s.replied != 1 {
		t.Fatalf("failure boundary or OpenVPN reply lost: %+v", s)
	}
	if s.currentMethod != "Xray" || s.recentMethod != "Xray" {
		t.Fatalf("current/latest method missing: %+v", s)
	}
}

func TestWindscribeVerboseRemainsAppendOnly(t *testing.T) {
	var out bytes.Buffer
	v := &wsProgressView{t: plainTerm(&out), verbose: true}
	s := wsProgressSnapshot{key: "203.0.113.100:443", total: 19, tried: 1, remaining: 18, attempted: 3, running: 2, replied: 1}
	v.show(s, true)
	if strings.Contains(out.String(), "\x1b[0J") {
		t.Fatal("redirected verbose output must not emit terminal redraw escapes")
	}
	if !strings.Contains(out.String(), "Started 3") || !strings.Contains(out.String(), "0 OpenVPN replies") && !strings.Contains(out.String(), "Running 2") {
		t.Fatalf("verbose status lost diagnostic counters: %s", out.String())
	}
	v.show(s, true)
	if strings.Count(out.String(), "WINDSCRIBE 203.0.113.100:443") != 1 {
		t.Fatalf("verbose progress should not repeat an unchanged status: %s", out.String())
	}
}

func TestWindscribeStatusDisplaysActiveMethodAndFailures(t *testing.T) {
	s := wsProgressSnapshot{
		total: 281, tried: 4, running: 16,
		currentMethod: "ByeDPI TLS record slicing", failStages: map[string]int{"tcp": 1, "tls": 3},
	}
	detail := wsLiveDetail(s, 160)
	for _, expected := range []string{"4/281 checked", "16 live", "ByeDPI TLS record slicing", "tcp=1", "tls=3"} {
		if !strings.Contains(detail, expected) {
			t.Fatalf("missing %q from live progress %q", expected, detail)
		}
	}
	if strings.Contains(wsLiveDetail(s, 40), "TLS record slicing") {
		t.Fatal("very narrow terminals should receive a compact status")
	}
	if !strings.Contains(wsLiveDetail(s, 80), "ByeDPI TLS") {
		t.Fatalf("standard 80-column output hid the current method: %q", wsLiveDetail(s, 80))
	}
}

func TestWindscribeLiveBoxContainsAllMethodCounters(t *testing.T) {
	var out bytes.Buffer
	v := &wsProgressView{t: &term{w: &out, live: true, unicode: true, columns: 105, rows: 38}}
	s := wsProgressSnapshot{key: "203.0.113.100:443", location: "Sweden / Stockholm - Fika", total: 57, tried: 7, remaining: 50, attempted: 10, running: 3,
		methods: []wsMethodProgress{
			{name: "ByeDPI TLS record slicing", total: 19, tried: 2, running: 1},
			{name: "ByeDPI double split", total: 19, tried: 5, running: 2},
			{name: "Xray local TCP fragment", total: 19},
		},
	}
	v.show(s, true)
	if v.t.pinnedBox == "" {
		t.Fatal("interactive box was not pinned")
	}
	for _, line := range []string{"WINDSCRIBE 203.0.113.100:443", "ByeDPI TLS record slicing", "ByeDPI double split", "Xray local TCP fragment", "2/19", "5/19", "50"} {
		if !strings.Contains(v.t.pinnedBox, line) {
			t.Fatalf("missing %q in boxed dashboard: %s", line, v.t.pinnedBox)
		}
	}
	first := v.t.pinnedBox
	// Force an update without waiting for the 3-second refresh window.
	v.last[s.key] = time.Now().Add(-time.Minute)
	s.tried, s.remaining = 8, 49
	s.methods[0].tried = 3
	v.show(s, true)
	if v.t.pinnedBox == first {
		t.Fatal("live box did not update counters")
	}
	if strings.Count(out.String(), "\x1b[0J") < 2 {
		t.Fatal("live box update failed to clear previous frame")
	}
	v.summary(s)
	if v.t.pinnedBox != "" {
		t.Fatal("session summary left the live box pinned")
	}
}

func TestWindscribePanelFitsNarrowTerminalAndShowsAllMethods(t *testing.T) {
	var out bytes.Buffer
	v := &wsProgressView{t: &term{w: &out, columns: 48, rows: 30, live: true, unicode: true}}
	s := wsProgressSnapshot{key: "203.0.113.100:443", total: 38, tried: 1, remaining: 37,
		methods: []wsMethodProgress{{name: "very long method title that should truncate", total: 19, tried: 1}, {name: "another method", total: 19}},
	}
	v.show(s, true)
	if v.t.pinnedBox == "" {
		t.Fatal("narrow but tall terminal should show a pinned box")
	}
	for _, row := range strings.Split(v.t.pinnedBox, "\n") {
		if visibleLen(row) > 48 {
			t.Fatalf("panel overflows narrow terminal: %q", row)
		}
	}
}

func TestWindscribeTallPanelFallsBackToScrollbackWithoutEscape(t *testing.T) {
	var out bytes.Buffer
	v := &wsProgressView{t: &term{w: &out, columns: 80, rows: 12, live: true, unicode: true}}
	s := wsProgressSnapshot{key: "203.0.113.100:443"}
	for i := 0; i < 19; i++ {
		s.methods = append(s.methods, wsMethodProgress{name: fmt.Sprintf("method-%02d", i), total: 19})
	}
	v.show(s, true)
	if v.t.pinnedBox != "" {
		t.Fatal("box taller than viewport must not use cursor pinning")
	}
	if !strings.Contains(out.String(), "method-18") {
		t.Fatal("short terminal fallback hid methods")
	}
}

func TestWindscribeTwoColumnPanelPinsNineteenMethodsInShortTerminal(t *testing.T) {
	var out bytes.Buffer
	v := &wsProgressView{t: &term{w: &out, columns: 88, rows: 24, live: true, unicode: true}}
	s := wsProgressSnapshot{key: "203.0.113.100:443", total: 19 * 19, remaining: 19 * 19}
	for i := 0; i < 19; i++ {
		s.methods = append(s.methods, wsMethodProgress{name: fmt.Sprintf("ByeDPI method %02d", i), total: 19})
	}
	v.show(s, true)
	if v.t.pinnedBox == "" {
		t.Fatal("nineteen methods should fit in a two-column pinned box")
	}
	for i := 0; i < 19; i++ {
		if !strings.Contains(v.t.pinnedBox, fmt.Sprintf("method %02d", i)) {
			t.Fatalf("method %d absent from two-column dashboard: %s", i, v.t.pinnedBox)
		}
	}
	for _, row := range strings.Split(v.t.pinnedBox, "\n") {
		if visibleLen(row) > 88 {
			t.Fatalf("two-column panel overflows terminal: %q", row)
		}
	}
	// Log lines are inserted above the pinned panel instead of erasing it.
	v.t.Line(toneWarn, "sample verbose carrier failure")
	if !strings.Contains(out.String(), "sample verbose carrier failure") || v.t.pinnedBox == "" {
		t.Fatal("logging did not retain the live panel")
	}
}

func TestWindscribeZeroCarriersExplainsMissingMappingInsteadOfFailedSearch(t *testing.T) {
	var out bytes.Buffer
	v := &wsProgressView{t: plainTerm(&out)}
	s := wsProgressSnapshot{
		key: "68.67.118.163:443", incomplete: true,
		mappingReason: "node not found in 2 fresh provider source(s)",
	}
	v.show(s, true)
	for _, want := range []string{"NO WRAPPED CARRIERS", "zero tests were run", "node not found in 2 fresh provider source(s)", "no IP guessing"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing diagnostic %q in %s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "all variants failed") {
		t.Fatal("missing discovery is not an anti-DPI failure")
	}
	v.summary(s)
	if !strings.Contains(out.String(), "No carrier variants were generated or tested") {
		t.Fatalf("end-of-session summary concealed missing catalog: %s", out.String())
	}
}
