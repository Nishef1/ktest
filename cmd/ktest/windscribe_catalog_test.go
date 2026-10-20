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
	// The scenario requires a strictly newer regional snapshot. Consecutive
	// time.Now calls can be equal on Windows and accidentally test a tie.
	fetched := time.Now()
	if err := c.replace("global", []byte(globalNodeFixture), fetched.Add(-time.Second)); err != nil {
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
	if err := c.replace("regional", []byte(strings.ReplaceAll(regionalNodeFixture, "node.example.com", "other.example.com")), fetched); err != nil {
		t.Fatal(err)
	}
	// Conflicting snapshots must not mix IPs across node identities.
	// The newer independently validated source remains eligible.
	if got := c.endpoints("203.0.113.100"); len(got) != 2 ||
		got[0].source != "regional/ip" || got[1].source != "regional/ip3" {
		t.Fatalf("conflicting node endpoints not isolated: %+v", got)
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
	want := []string{"198.51.100.9:443", "198.51.100.9:443", "198.51.100.9:443", "192.0.2.210:443", "192.0.2.210:443", "192.0.2.210:443", "192.0.2.210:443", "192.0.2.210:443"}
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

func TestCatalogKeepsUnmodifiedNodesWhenRegionalResponseIsAltered(t *testing.T) {
	// The observed IR response was valid and populated, but omitted the
	// app-selected Ashburn TCP entry. Only country_override=ZZ supplied it.
	const unmodified = `{"data":[{"name":"US East","groups":[{"city":"Ashburn","nick":"Bles Park","nodes":[{"ip":"152.233.50.129","ip2":"152.233.50.130","ip3":"152.233.50.131","hostname":"us-east-197.whiskergalaxy.com"}]}]}]}`
	var regionalRequests, unmodifiedRequests int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("country_override") == "ZZ" {
			unmodifiedRequests++
			_, _ = w.Write([]byte(unmodified))
		} else {
			regionalRequests++
			_, _ = w.Write([]byte(globalNodeFixture))
		}
	}))
	defer srv.Close()
	c := newWSNodeCatalog()
	for _, configured := range wsCatalogURLs {
		source := configured
		source.url = strings.Replace(source.url, "https://assets.windscribe.com", srv.URL, 1)
		source.fallback = ""
		if err := c.updateFromSource(context.Background(), srv.Client(), source); err != nil {
			t.Fatal(err)
		}
	}
	if regionalRequests == 0 || unmodifiedRequests == 0 {
		t.Fatalf("both routing inventories are required even when the first succeeds: regional=%d unmodified=%d", regionalRequests, unmodifiedRequests)
	}
	for _, catalog := range []*wsNodeCatalog{c, newWSNodeCatalog()} {
		if catalog != c {
			path := filepath.Join(t.TempDir(), "catalog.json")
			if err := c.save(path); err != nil {
				t.Fatal(err)
			}
			catalog.load(path)
		}
		if got := catalog.endpoints("152.233.50.130"); len(got) != 2 || got[0].ip != "152.233.50.129" || got[1].ip != "152.233.50.131" {
			t.Fatalf("app-selected node still has no exact provider mapping: %+v", got)
		}
		if got := catalog.endpoints("203.0.113.100"); len(got) != 2 {
			t.Fatalf("regional inventory was lost: %+v", got)
		}
		if got := catalog.endpoints("152.233.50.146"); len(got) != 0 {
			t.Fatalf("a neighboring TCP target inherited the node: %+v", got)
		}
	}
}

func TestCatalogTimestampPrecedesCountryOverrideQuery(t *testing.T) {
	got := wsCatalogRequestURL("https://assets.windscribe.com/serverlist/mob-v2/1/?country_override=ZZ", time.Unix(1760700000, 0))
	if got != "https://assets.windscribe.com/serverlist/mob-v2/1/1760700000?country_override=ZZ" {
		t.Fatalf("timestamp lost or appended to the country override: %s", got)
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

func TestCatalogWaitsForRequestedNodeNotUnrelatedValidSource(t *testing.T) {
	c := newWSNodeCatalog()
	c.beginFetch()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan bool, 1)
	go func() { result <- c.waitForTarget(ctx, "203.0.113.200", 900*time.Millisecond) }()
	if err := c.replace("global", []byte(globalNodeFixture), time.Now()); err != nil {
		t.Fatal(err)
	}
	c.finishFetch()
	select {
	case <-result:
		t.Fatal("an unrelated node caused early completion")
	case <-time.After(25 * time.Millisecond):
	}
	other := []byte(`{"data":[{"nodes":[{"ip":"198.51.100.20","ip2":"203.0.113.200","ip3":"192.0.2.20","hostname":"second.example.com"}]}]}`)
	if err := c.replace("regional", other, time.Now()); err != nil {
		t.Fatal(err)
	}
	c.finishFetch()
	select {
	case ok := <-result:
		if !ok {
			t.Fatal("requested node did not awaken its waiter")
		}
	case <-time.After(time.Second):
		t.Fatal("target lookup remained blocked")
	}
}

func TestCatalogConflictingSnapshotsKeepNewerValidatedNodeIsolated(t *testing.T) {
	c := newWSNodeCatalog()
	now := time.Now()
	if err := c.replace("global", []byte(globalNodeFixture), now); err != nil {
		t.Fatal(err)
	}
	other := []byte(strings.ReplaceAll(regionalNodeFixture, "node.example.com", "other.example.com"))
	if err := c.replace("regional", other, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	want := []wsEndpoint{{"192.0.2.80", "regional/ip"}, {"198.51.100.240", "regional/ip3"}}
	if got := c.endpoints("203.0.113.100"); !reflect.DeepEqual(got, want) {
		t.Fatalf("provider conflict mixed endpoints or discarded valid newer node: %+v", got)
	}
}

func TestCatalogMissingTargetDiagnosedAndRetriedWithoutInventedIPs(t *testing.T) {
	c := newWSNodeCatalog()
	target := "203.0.113.200"
	c.beginFetch()
	if err := c.replace("global", []byte(globalNodeFixture), time.Now()); err != nil {
		t.Fatal(err)
	}
	c.finishFetch()
	c.mu.Lock()
	c.sourceErrors["regional"] = "HTTP 503"
	c.mu.Unlock()
	for range len(wsCatalogURLs) - 1 {
		c.finishFetch()
	}
	if c.waitForTarget(context.Background(), target, time.Millisecond) {
		t.Fatal("unrelated fresh list was accepted for missing target")
	}
	if !c.hasUnresolvedTargets() {
		t.Fatal("unresolved requested target was not remembered for retry")
	}
	detail := c.diagnostic(target)
	if !strings.Contains(detail, "node not found in 1 fresh provider source") || !strings.Contains(detail, "regional: HTTP 503") {
		t.Fatalf("missing-node diagnostic not actionable: %q", detail)
	}
	if got := c.endpoints(target); len(got) != 0 {
		t.Fatalf("unsafe inferred endpoint: %+v", got)
	}
	const recovered = `{"data":[{"nodes":[{"ip":"198.51.100.20","ip2":"203.0.113.200","ip3":"192.0.2.20","hostname":"example.windscribe.com"}]}]}`
	if err := c.replace("regional", []byte(recovered), time.Now()); err != nil {
		t.Fatal(err)
	}
	if c.hasUnresolvedTargets() || len(c.endpoints(target)) != 2 {
		t.Fatal("fresh provider mapping did not resolve the pending target")
	}
	if strings.Contains(c.diagnostic(target), "HTTP 503") {
		t.Fatal("stale fetch failure was kept after successful replacement")
	}
}

func TestCatalogRefreshDelayDistinguishesMissingNodeFromSuccessfulFetch(t *testing.T) {
	for _, tc := range []struct {
		refreshed, missing bool
		retries            int
		want               time.Duration
	}{
		{true, false, 0, 30 * time.Minute},
		{false, false, 0, 30 * time.Second},
		{true, true, 0, 45 * time.Second},
		{true, true, 1, 5 * time.Minute},
		{true, true, 100, 5 * time.Minute},
	} {
		if got := wsCatalogRefreshDelay(tc.refreshed, tc.missing, tc.retries); got != tc.want {
			t.Fatalf("refresh=%t missing=%t retries=%d: got %s want %s", tc.refreshed, tc.missing, tc.retries, got, tc.want)
		}
	}
}

func TestCatalogHedgesStalledPrimaryBeforeFirstWindscribeConnect(t *testing.T) {
	var fallbackCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mob":
			<-r.Context().Done() // censored/blocked API: must not prevent fallback
		case "/legacy":
			fallbackCalls++
			_, _ = w.Write([]byte(globalNodeFixture))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c := newWSNodeCatalog()
	start := time.Now()
	err := c.updateFromSource(ctx, srv.Client(), wsCatalogSource{
		name: "global", url: srv.URL + "/mob", fallback: srv.URL + "/legacy",
	})
	if err != nil || len(c.endpoints("203.0.113.100")) == 0 || fallbackCalls == 0 {
		t.Fatalf("blocked mob-v2 prevented valid legacy node discovery: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("legacy catalog was not hedged inside first CONNECT wait: %v", d)
	}
}

func TestCatalogInvalidPrimaryFallsBackWithoutPublishingBadNodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mob" {
			_, _ = w.Write([]byte("{malformed"))
			return
		}
		_, _ = w.Write([]byte(regionalNodeFixture))
	}))
	defer srv.Close()
	c := newWSNodeCatalog()
	if err := c.updateFromSource(context.Background(), srv.Client(), wsCatalogSource{
		name: "regional", url: srv.URL + "/mob", fallback: srv.URL + "/legacy",
	}); err != nil {
		t.Fatalf("valid fallback rejected after malformed primary: %v", err)
	}
	if got := c.endpoints("203.0.113.100"); len(got) == 0 || got[0].source != "regional/ip" {
		t.Fatalf("unverified primary response poisoned provider nodes: %+v", got)
	}
}

func TestCatalogFastPrimaryDoesNotDownloadFallback(t *testing.T) {
	var fallbackCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/legacy" {
			fallbackCalls++
			http.Error(w, "not needed", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(globalNodeFixture))
	}))
	defer srv.Close()
	c := newWSNodeCatalog()
	if err := c.updateFromSource(context.Background(), srv.Client(), wsCatalogSource{
		name: "global", url: srv.URL + "/mob", fallback: srv.URL + "/legacy",
	}); err != nil || fallbackCalls != 0 {
		t.Fatalf("healthy fast primary needlessly loaded legacy catalog: %v, requests=%d", err, fallbackCalls)
	}
}

func TestPartialWindscribeCatalogRefreshAvoidsFullRetryFlood(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/okay") {
			_, _ = w.Write([]byte(globalNodeFixture))
			return
		}
		http.Error(w, "restricted regional API", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	oldSources := wsCatalogURLs
	wsCatalogURLs = []wsCatalogSource{
		{name: "global", url: srv.URL + "/okay/", fallback: srv.URL + "/okay-fallback"},
		{name: "regional", url: srv.URL + "/blocked/", fallback: srv.URL + "/blocked-fallback"},
	}
	defer func() { wsCatalogURLs = oldSources }()
	c := newWSNodeCatalog()
	refreshed := c.refresh(context.Background(), srv.Client(), filepath.Join(t.TempDir(), "nodes.json"), func(string, ...any) {})
	if !refreshed || len(c.endpoints("203.0.113.100")) == 0 {
		t.Fatal("one working official list must unblock the exact Windscribe node")
	}
	if next := wsCatalogRefreshDelay(refreshed, false, 0); next != 30*time.Minute {
		t.Fatalf("partial provider outage causes repeated full inventory downloads: %s", next)
	}
	if next := wsCatalogRefreshDelay(refreshed, true, 0); next != 45*time.Second {
		t.Fatalf("missing target was not scheduled for prompt recovery: %s", next)
	}
}
