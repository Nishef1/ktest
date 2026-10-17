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
