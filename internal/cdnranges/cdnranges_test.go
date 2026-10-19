package cdnranges

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestUsableAggregatesAndDropsBogons(t *testing.T) {
	v4, v6 := usable([]string{"23.0.0.0/12", "23.1.2.0/24", "10.0.0.0/8", "1.0.0.0/4", "104.16.0.0/13", "2600:1400::/24", "fd00::/8", "192.0.2.7", "198.51.100.0/24", "8.8.8.8", "2001:db8::/32"})
	if strings.Join(v4, ",") != "8.8.8.8/32,23.0.0.0/12,104.16.0.0/13" || strings.Join(v6, ",") != "2600:1400::/24" {
		t.Fatalf("v4 %v v6 %v", v4, v6)
	}
}

func TestSampleZeroOrNegativeBudgetDoesNotExpandToWholeInventory(t *testing.T) {
	s := &Set{Version: 1, Providers: map[string]*Range{"akamai": {V4: []string{"2.16.0.0/23"}}}}
	for _, budget := range []int{0, -1} {
		if got := s.Sample("akamai", budget); len(got) != 0 {
			t.Fatalf("budget %d unexpectedly returned %d addresses", budget, len(got))
		}
	}
	if got := s.Sample("akamai", 4); len(got) != 4 {
		t.Fatalf("positive sample budget returned %d addresses, want 4", len(got))
	}
}

func TestFallbackReportsPreserveEarlierProviderSuccesses(t *testing.T) {
	first := []Report{{Provider: "cloudflare", Prefixes: 8, Source: "direct"},
		{Provider: "fastly", Err: context.DeadlineExceeded}}
	fallback := []Report{{Provider: "cloudflare", Err: context.DeadlineExceeded},
		{Provider: "fastly", Prefixes: 12, Source: "proxy"}}
	if !ReportsHaveFailures(first) || !ReportsHaveFailures(fallback) {
		t.Fatal("provider-level failures were not detected")
	}
	combined := CombineReports(first, fallback)
	if len(combined) != 2 || combined[0].Provider != "cloudflare" || combined[0].Source != "direct" ||
		combined[1].Provider != "fastly" || combined[1].Source != "proxy" {
		t.Fatalf("combined reports lost the best outcome per provider: %+v", combined)
	}
	if ReportsHaveFailures(combined) {
		t.Fatalf("a provider with at least one successful route is still reported failed: %+v", combined)
	}
}

func TestLoadRevalidatesCachedProviderPrefixes(t *testing.T) {
	dir := t.TempDir()
	previous := Current()
	t.Cleanup(func() { Use(previous) })
	cache := &Set{Version: 1, Providers: map[string]*Range{
		"cloudflare": {V4: []string{"127.0.0.0/8", "192.0.2.0/24", "104.16.0.0/13"},
			V6: []string{"2001:db8::/32", "2606:4700::/32"}, Updated: time.Now().UTC(), Source: "test cache"},
	}}
	if err := Save(dir, cache); err != nil {
		t.Fatal(err)
	}
	loaded := Load(dir)
	for _, ip := range []string{"127.0.0.1", "192.0.2.1", "2001:db8::1"} {
		if loaded.Contains("cloudflare", ip) {
			t.Errorf("special-use cached address %s was accepted", ip)
		}
	}
	for _, ip := range []string{"104.16.0.1", "2606:4700::1"} {
		if !loaded.Contains("cloudflare", ip) {
			t.Errorf("valid cached address %s was dropped", ip)
		}
	}
}

func TestIteratorSpreadsAndSkipsNetworkAddresses(t *testing.T) {
	s := &Set{Version: 1, Providers: map[string]*Range{"akamai": {V4: []string{"2.16.0.0/23", "23.32.0.0/24"}}}}
	next := s.Iterator("akamai", 0, 7)
	seen := map[string]bool{}
	first := map[string]bool{}
	for i := 0; ; i++ {
		ip, ok, err := next(context.Background())
		if err != nil || !ok {
			break
		}
		if seen[ip] || strings.HasSuffix(ip, ".0") || strings.HasSuffix(ip, ".255") {
			t.Fatalf("bad candidate %s", ip)
		}
		seen[ip] = true
		if i < 2 {
			first[strings.Join(strings.Split(ip, ".")[:2], ".")] = true
		}
	}
	if len(seen) != 3*254 || s.Size("akamai") != 3*254 {
		t.Fatalf("emitted %d, size %d", len(seen), s.Size("akamai"))
	}
	if len(first) != 2 {
		t.Fatalf("first candidates must come from different prefixes: %v", first)
	}
	if !s.Contains("akamai", "23.32.0.9") || s.ProviderOf("2.16.1.4") != "akamai" || s.ProviderOf("8.8.8.8") != "" {
		t.Fatal("membership")
	}
}

func TestEmbeddedSnapshotCoversEveryProvider(t *testing.T) {
	s := snapshot()
	for _, p := range Providers {
		if s.Size(p) < 500 {
			t.Errorf("%s: only %d addresses embedded", p, s.Size(p))
		}
	}
	if !s.Contains("cloudflare", "104.16.1.1") || !s.Contains("google", "142.250.1.1") {
		t.Fatal("well-known edges missing")
	}
}

type fakeTransport map[string]string

func (f fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body, ok := f[r.URL.String()]
	code := http.StatusOK
	if !ok {
		code, body = http.StatusForbidden, `{"errors":[{"title":"Restricted Country or Region"}]}`
	}
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: r}, nil
}

func TestRefreshKeepsGoodProvidersAndRefusesShrinking(t *testing.T) {
	dir := t.TempDir()
	responses := fakeTransport{
		"https://www.cloudflare.com/ips-v4": "104.16.0.0/13\n104.24.0.0/14\n108.162.192.0/18\n141.101.64.0/18\n162.158.0.0/15\n172.64.0.0/13\n188.114.96.0/20\n198.41.128.0/17\n",
		"https://www.cloudflare.com/ips-v6": "2606:4700::/32\n",
		// Fastly's API is geo-blocked: the ASN fallback must answer instead.
		"https://stat.ripe.net/data/as-overview/data.json?resource=AS54113":        `{"data":{"holder":"FASTLY - Fastly, Inc."}}`,
		"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS54113": `{"data":{"prefixes":[{"prefix":"151.101.0.0/16"},{"prefix":"146.75.0.0/17"}]}}`,
	}
	client := &http.Client{Transport: responses}
	reports, err := Refresh(context.Background(), client, dir)
	if err != nil {
		t.Fatal(err, reports)
	}
	byName := map[string]Report{}
	for _, r := range reports {
		byName[r.Provider] = r
	}
	// Cloudflare's tiny official list is plausible; Fastly's two prefixes are
	// far fewer than the embedded inventory and must be refused.
	if byName["cloudflare"].Err != nil || byName["fastly"].Err == nil || !strings.Contains(byName["fastly"].Err.Error(), "shrink") {
		t.Fatalf("reports %v", reports)
	}
	loaded := Load(dir)
	if r := loaded.Providers["cloudflare"]; r == nil || time.Since(r.Updated) > time.Minute || len(r.V4) != 8 {
		t.Fatalf("cloudflare not refreshed: %+v", r)
	}
	if loaded.Size("fastly") != snapshot().Size("fastly") || loaded.Size("akamai") == 0 {
		t.Fatal("failed providers must keep their previous inventory")
	}
	if Current() != loaded {
		t.Fatal("loaded inventory not installed")
	}
}
