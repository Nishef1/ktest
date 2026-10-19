package front

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Nishef1/ktest/internal/cdnranges"
)

func TestFilteredResolverFallsBackToTheProvidersInventory(t *testing.T) {
	previous := cdnranges.Current()
	cdnranges.Use(&cdnranges.Set{Version: 1, Providers: map[string]*cdnranges.Range{
		"akamai": {V4: []string{"23.32.0.0/30"}, Updated: time.Now()},
	}})
	t.Cleanup(func() { cdnranges.Use(previous) })
	var mu sync.Mutex
	var dialed []string
	f := New(Config{
		Resolve: func(context.Context, string) ([]string, error) { return nil, errors.New("filtered") },
		dial: func(_ context.Context, addr string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, addr)
			mu.Unlock()
			return nil, errors.New("refused")
		},
	})
	fam := &Family{Name: "edge", Provider: "akamai", Domains: []string{"site.example"}, NoStandIn: []string{"video.site.example"}}
	if _, err := f.try(context.Background(), fam, Front{SNI: "front.example"}, "www.site.example", []string{"h2"}); err == nil {
		t.Fatal("refused dials cannot succeed")
	}
	mu.Lock()
	got := append([]string(nil), dialed...)
	dialed = nil
	mu.Unlock()
	if len(got) == 0 {
		t.Fatal("no inventory edge was tried after DNS failed")
	}
	for _, addr := range got {
		host, _, _ := net.SplitHostPort(addr)
		if !netip.MustParsePrefix("23.32.0.0/30").Contains(netip.MustParseAddr(host)) {
			t.Fatalf("dialed %s outside the provider inventory", addr)
		}
	}
	// A host only its own servers can serve never gets a stand-in edge.
	_, _ = f.try(context.Background(), fam, Front{SNI: "front.example"}, "video.site.example", []string{"h2"})
	mu.Lock()
	defer mu.Unlock()
	if len(dialed) != 0 {
		t.Fatalf("stand-in edges dialed for a NoStandIn host: %v", dialed)
	}
}
