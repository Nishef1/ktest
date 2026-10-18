package main

import (
	"bytes"
	"context"
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

func TestWindscribeInventoryNamesEveryMethodAndKeepsTLSOnlyOffRawVPN(t *testing.T) {
	b := newWSBridge(wsOptions{direct: true, sni: "example.com", serverIP: "198.51.100.10"}, nil, nil, func(string, ...any) {})
	b.methods = func() []smartproxy.WindscribeMethod {
		return []smartproxy.WindscribeMethod{{Name: "ByeDPI A"}, {Name: "ByeDPI B"}, {Name: "TLS cut", TLSOnly: true}, {Name: "IPv6 cut", TLSOnly: true, IPv6Only: true}}
	}
	seen := make(map[string]int)
	for _, c := range b.carriersFor("203.0.113.100") {
		seen[c.method]++
		if strings.HasPrefix(c.name, "raw OpenVPN") && c.method == "TLS cut" {
			t.Fatal("ClientHello shaping offered to raw OpenVPN")
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
