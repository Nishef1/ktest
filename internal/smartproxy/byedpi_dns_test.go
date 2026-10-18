package smartproxy

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestByeDPILocalDNSFailureDoesNotUseSystemResolver(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resolver Resolver
	}{
		{name: "missing trusted resolver"},
		{name: "trusted resolver unavailable", resolver: func(context.Context, string) ([]string, error) {
			return nil, errors.New("trusted DNS offline")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			upstream := fakeSocks(t, destination(t), true, &hits)
			p, err := New(Config{
				Upstreams: []Upstream{{Name: "ByeDPI local", Addr: upstream, LocalDNS: true, LocalBypass: true}},
				Resolve:   tc.resolver,
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if conn, err := p.DialLocalBypass(ctx, "blocked.example", "443"); err == nil {
				conn.Close()
				t.Fatal("ByeDPI received a hostname after trusted DNS failed")
			}
			if hits.Load() != 0 {
				t.Fatalf("ByeDPI contacted %d times despite failed trusted DNS", hits.Load())
			}
		})
	}
}

func TestByeDPINumericDestinationsRemainUsableWithoutDNS(t *testing.T) {
	var hits atomic.Int32
	upstream := fakeSocks(t, destination(t), true, &hits)
	p, err := New(Config{Upstreams: []Upstream{
		{Name: "ByeDPI numeric", Addr: upstream, LocalDNS: true, LocalBypass: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := p.DialLocalBypass(ctx, "198.51.100.10", "443")
	if err != nil {
		t.Fatalf("DNS gate blocked a numeric Windscribe endpoint: %v", err)
	}
	_ = conn.Close()
	if hits.Load() != 1 {
		t.Fatalf("expected one SOCKS connection, got %d", hits.Load())
	}
}
