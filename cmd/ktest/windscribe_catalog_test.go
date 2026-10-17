package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCatalogFetchRejectsFailureAndOversizedResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		ok     bool
	}{
		{"valid", 200, globalNodeFixture, true},
		{"server failure", 503, globalNodeFixture, false},
		{"oversized", 200, strings.Repeat("x", wsCatalogLimit+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			body, err := fetchWSNodeList(context.Background(), srv.Client(), srv.URL)
			if (err == nil) != tc.ok {
				t.Fatalf("unexpected response acceptance: %v", err)
			}
			if tc.ok && string(body) != tc.body {
				t.Fatal("provider response changed")
			}
		})
	}
}

const globalNodeFixture = `{"data":[{"nodes":[{"ip":"198.51.100.9","ip2":"203.0.113.100","ip3":"192.0.2.210","hostname":"node.example.com","group":"Example - A"}]}]}`
const regionalNodeFixture = `{"data":[{"nodes":[{"ip":"192.0.2.80","ip2":"203.0.113.100","ip3":"198.51.100.240","hostname":"node.example.com","group":"Example - A"}]}]}`

func TestCatalogUsesBothProviderListsForExactNode(t *testing.T) {
	c := newWSNodeCatalog()
	for source, body := range map[string]string{"global": globalNodeFixture, "regional": regionalNodeFixture} {
		if err := c.replace(source, []byte(body), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	want := []wsEndpoint{{"198.51.100.9", "global/ip"}, {"192.0.2.210", "global/ip3"}, {"192.0.2.80", "regional/ip"}, {"198.51.100.240", "regional/ip3"}}
	if got := c.endpoints("203.0.113.100"); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if got := c.endpoints("203.0.113.101"); len(got) != 0 {
		t.Fatalf("different node inherited endpoints: %+v", got)
	}
	path := filepath.Join(t.TempDir(), "cache", "windscribe-nodes.json")
	if err := c.save(path); err != nil {
		t.Fatal(err)
	}
	// Refresh must also replace an existing cache on Windows.
	if err := c.save(path); err != nil {
		t.Fatal(err)
	}
	loaded := newWSNodeCatalog()
	loaded.load(path)
	if got := loaded.endpoints("203.0.113.100"); !reflect.DeepEqual(got, want) {
		t.Fatalf("fresh cache lost provenance or endpoints: %+v", got)
	}
}

func TestCatalogRejectsUnsafeAmbiguousAndStaleMappings(t *testing.T) {
	c := newWSNodeCatalog()
	if err := c.replace("global", []byte(globalNodeFixture), time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"data":[]}`,
		`{"data":[{"nodes":[{"ip":"127.0.0.1","ip2":"203.0.113.100","ip3":"192.0.2.210","hostname":"node.example.com"}]}]}`,
		`{"data":[{"nodes":[{"ip":"198.51.100.9","ip2":"203.0.113.100","ip3":"192.0.2.210","hostname":"node.example.com"},{"ip":"198.51.100.8","ip2":"203.0.113.100","ip3":"192.0.2.209","hostname":"other.example.com"}]}]}`,
		strings.Repeat(" ", wsCatalogLimit+1),
	} {
		if err := c.replace("global", []byte(body), time.Now()); err == nil {
			t.Fatal("invalid provider update accepted")
		}
		if got := c.endpoints("203.0.113.100"); len(got) != 2 {
			t.Fatalf("invalid update destroyed fresh data: %+v", got)
		}
	}
	if err := c.replace("regional", []byte(strings.ReplaceAll(regionalNodeFixture, "node.example.com", "other.example.com")), time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := c.endpoints("203.0.113.100"); len(got) != 0 {
		t.Fatalf("mixed conflicting node identities: %+v", got)
	}
	for _, fetched := range []time.Time{time.Now().Add(-wsCatalogMaxAge - time.Minute), time.Now().Add(time.Hour)} {
		c = newWSNodeCatalog()
		if err := c.replace("global", []byte(globalNodeFixture), fetched); err != nil {
			t.Fatal(err)
		}
		if got := c.endpoints("203.0.113.100"); len(got) != 0 {
			t.Fatalf("expired/future mapping used: %+v", got)
		}
	}
}

func TestCarriersActuallyDialAdvertisedNonNeighbourAddresses(t *testing.T) {
	b := newWSBridge(wsOptions{direct: true, sni: "www.speedtest.net"}, nil, nil, func(string, ...any) {})
	b.catalog = newWSNodeCatalog()
	if err := b.catalog.replace("global", []byte(globalNodeFixture), time.Now()); err != nil {
		t.Fatal(err)
	}
	var targets []string
	b.carrierLocal = func(_ context.Context, h, p string) (net.Conn, error) {
		targets = append(targets, net.JoinHostPort(h, p))
		return nil, errors.New("probe stopped before network")
	}
	for _, carrier := range b.carriersFor("203.0.113.100") {
		if strings.Contains(carrier.name, "+anti-DPI") && carrier.name != "raw OpenVPN +anti-DPI" {
			_, _ = carrier.open(context.Background(), "203.0.113.100", "443")
		}
	}
	want := []string{"198.51.100.9:443", "198.51.100.9:443", "192.0.2.210:443", "192.0.2.210:443", "192.0.2.210:443", "192.0.2.210:443"}
	if !reflect.DeepEqual(targets, want) {
		t.Fatalf("wrong carrier destinations: %v, want %v", targets, want)
	}
}

func TestAdvertisedStealthEndpointDoesNotRequireWStunnelCertificateName(t *testing.T) {
	// The official Stealth wrapper authenticates the inner OpenVPN server;
	// its outer TLS certificate need not name a windscribe.com host.
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	b := newWSBridge(wsOptions{direct: true, sni: "www.speedtest.net"}, nil, nil, func(string, ...any) {})
	b.catalog = newWSNodeCatalog()
	if err := b.catalog.replace("global", []byte(globalNodeFixture), time.Now()); err != nil {
		t.Fatal(err)
	}
	b.carrierLocal = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}
	for _, carrier := range b.carriersFor("203.0.113.100") {
		if strings.HasPrefix(carrier.name, "Stealth ") && strings.Contains(carrier.name, "+anti-DPI") && carrier.addr == "192.0.2.210:443" {
			c, err := carrier.open(context.Background(), "203.0.113.100", "443")
			if err != nil {
				t.Fatalf("provider-advertised Stealth endpoint rejected by outer TLS name: %v", err)
			}
			_ = c.Close()
			return
		}
	}
	t.Fatal("advertised Stealth carrier missing")
}

func TestStealthOnlyTargetsOfficialProviderIP3(t *testing.T) {
	b := newWSBridge(wsOptions{direct: true, sni: "a.example"}, nil, nil, func(string, ...any) {})
	b.catalog = newWSNodeCatalog()
	if err := b.catalog.replace("global", []byte(globalNodeFixture), time.Now()); err != nil {
		t.Fatal(err)
	}
	var stealth int
	for _, candidate := range b.carriersFor("203.0.113.100") {
		if !strings.HasPrefix(candidate.name, "Stealth ") {
			continue
		}
		stealth++
		if candidate.addr != "192.0.2.210:443" || !strings.HasSuffix(candidate.source, "/ip3") {
			t.Fatalf("Stealth tested a non-ip3 endpoint: %+v", candidate)
		}
	}
	if stealth != 4 {
		t.Fatalf("expected both client-hello profiles on direct and local ip3 Stealth, got %d", stealth)
	}
	b.opts.serverIP = "198.51.100.55"
	for _, candidate := range b.carriersFor("203.0.113.100") {
		if strings.HasPrefix(candidate.name, "Stealth ") {
			t.Fatalf("explicit WStunnel IP override created an unrelated Stealth route: %+v", candidate)
		}
	}
}

// The provider can reuse an IPv4 for the general and Stealth fields.
// The mixed-address dedupe must never erase protocol-specific provenance.
func TestStealthKeepsIP3WhenItAliasesGeneralIP(t *testing.T) {
	c := newWSNodeCatalog()
	body := []byte(`{"data":[{"nodes":[{"ip":"198.51.100.9","ip2":"203.0.113.100","ip3":"198.51.100.9","hostname":"node.example.com"}]}]}`)
	if err := c.replace("global", body, time.Now()); err != nil {
		t.Fatal(err)
	}
	ep := c.endpointsByField("203.0.113.100", "ip3")
	if len(ep) != 1 || ep[0].ip != "198.51.100.9" || ep[0].source != "global/ip3" {
		t.Fatalf("Stealth IP3 was erased by general-address dedupe: %+v", ep)
	}
	b := newWSBridge(wsOptions{direct: true, sni: "example.com"}, nil, nil, func(string, ...any) {})
	b.catalog = c
	var found bool
	for _, carrier := range b.carriersFor("203.0.113.100") {
		if strings.HasPrefix(carrier.name, "Stealth ") && carrier.addr == "198.51.100.9:443" {
			found = true
		}
	}
	if !found {
		t.Fatal("legitimate aliased Stealth endpoint vanished from carriers")
	}
}

func TestWindscribeCatalogParsesCurrentMobV2NestedGroups(t *testing.T) {
	// Windscribe's public mob-v2 schema nests nodes under location groups.
	// Empty groups are valid and must not invalidate other reachable nodes.
	body := []byte(`{"data":[{"name":"US East","groups":[{"city":"Chicago","nick":"Cub","nodes":[{"ip":"198.51.100.10","ip2":"203.0.113.100","ip3":"192.0.2.10","hostname":"us-east-101.whiskergalaxy.com"}]},{"city":"Boston","nick":"Tea Party"},{"city":"New York","nodes":[{"ip":"198.51.100.20","ip2":"203.0.113.200","ip3":"192.0.2.20","hostname":"us-east-102.whiskergalaxy.com"}]}]}]}`)
	c := newWSNodeCatalog()
	if err := c.replace("global", body, time.Now()); err != nil {
		t.Fatal(err)
	}
	for tcp, expected := range map[string]string{"203.0.113.100": "192.0.2.10", "203.0.113.200": "192.0.2.20"} {
		entries := c.endpointsByField(tcp, "ip3")
		if len(entries) != 1 || entries[0].ip != expected {
			t.Fatalf("mob-v2 nested node %s omitted: %+v", tcp, entries)
		}
	}
}

func TestWindscribeMobV2ProviderURLAndLegacyFallback(t *testing.T) {
	base := "https://assets.windscribe.com/serverlist/mob-v2/1/"
	got := wsCatalogRequestURL(base, time.Unix(1760700000, 0))
	if got != base+"1760700000" {
		t.Fatalf("mob-v2 timestamp URL %q", got)
	}
	var v2, legacy int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mob-v2":
			v2++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"groups":[{"city":"Empty"}]}]}`))
		case "/legacy":
			legacy++
			_, _ = w.Write([]byte(globalNodeFixture))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := newWSNodeCatalog()
	if err := c.updateFromSource(context.Background(), srv.Client(), wsCatalogSource{
		name: "global", url: srv.URL + "/mob-v2", fallback: srv.URL + "/legacy",
	}); err != nil {
		t.Fatal(err)
	}
	if v2 != 1 || legacy != 1 {
		t.Fatalf("legacy API fallback not reached after invalid mob-v2 list: v2=%d legacy=%d", v2, legacy)
	}
	if len(c.endpoints("203.0.113.100")) != 2 {
		t.Fatal("usable legacy catalog was not retained")
	}
}

func TestWindscribeCatalogAvoidsForceDisconnectNodes(t *testing.T) {
	// wsnet 1.5.33 exposes fd:1, instructing clients to avoid starting
	// new connections on a draining server even in an otherwise healthy city.
	body := []byte(`{"data":[{"groups":[{"nodes":[{"ip":"192.0.2.10","ip2":"203.0.113.10","ip3":"198.51.100.10","hostname":"old.windscribe.com","fd":1},{"ip":"192.0.2.20","ip2":"203.0.113.20","ip3":"198.51.100.20","hostname":"new.windscribe.com","fd":0}]}]}]}`)
	nodes, err := parseWSNodes(body)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := nodes["203.0.113.10"]; exists {
		t.Fatal("draining server became an eligible carrier")
	}
	if _, exists := nodes["203.0.113.20"]; !exists {
		t.Fatal("healthy server removed with draining server")
	}
}

// wsnet's official InventoryParser permits an ip3 null: Stealth is unavailable
// for that node, while the advertised TCP and general-IP routes remain usable.
func TestWindscribeCatalogAcceptsNullIP3AndSkipsIsolatedInvalidNodes(t *testing.T) {
	c := newWSNodeCatalog()
	body := []byte(`{"data":[{"nodes":[
		{"ip":"198.51.100.12","ip2":"203.0.113.12","ip3":null,"hostname":"first.windscribe.com"},
		{"ip":"127.0.0.1","ip2":"203.0.113.99","ip3":"192.0.2.99","hostname":"invalid.windscribe.com"},
		{"ip":"198.51.100.13","ip2":"203.0.113.13","ip3":"192.0.2.13","hostname":"second.windscribe.com"}
	]}]}`)
	if err := c.replace("global", body, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := c.endpoints("203.0.113.12"); !reflect.DeepEqual(got, []wsEndpoint{{"198.51.100.12", "global/ip"}}) {
		t.Fatalf("null ip3 discarded legitimate OpenVPN mapping or created bogus endpoint: %+v", got)
	}
	if got := c.endpointsByField("203.0.113.12", "ip3"); len(got) != 0 {
		t.Fatalf("null ip3 created fake Stealth route: %+v", got)
	}
	if got := c.endpoints("203.0.113.13"); len(got) != 2 {
		t.Fatalf("valid sibling lost alongside malformed node: %+v", got)
	}
	if got := c.endpoints("203.0.113.99"); len(got) != 0 {
		t.Fatalf("malformed node survived validation: %+v", got)
	}
	select {
	case <-c.ready:
	default:
		t.Fatal("valid catalog did not signal readiness")
	}
}

// A successful provider source must unblock a waiting CONNECT without waiting
// for a different source to time out. This is particularly important behind DPI.
func TestWindscribeCatalogReadyBeforeSlowSourceCompletes(t *testing.T) {
	old := wsCatalogURLs
	defer func() { wsCatalogURLs = old }()
	slowEntered := make(chan struct{}, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			select {
			case slowEntered <- struct{}{}:
			default:
			}
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte(globalNodeFixture))
	}))
	defer srv.Close()
	wsCatalogURLs = []wsCatalogSource{
		{name: "slow", url: srv.URL + "/slow"},
		{name: "global", url: srv.URL + "/fast"},
	}
	c := newWSNodeCatalog()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.run(ctx, srv.Client(), filepath.Join(t.TempDir(), "cache.json"), func(string, ...any) {})
	}()
	select {
	case <-slowEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("slow provider was not requested")
	}
	select {
	case <-c.ready:
		if got := c.endpoints("203.0.113.100"); len(got) != 2 {
			t.Fatalf("catalog signaled ready without usable endpoints: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ready blocked behind a slow alternate provider")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("catalog fetch did not cancel cleanly")
	}
}
