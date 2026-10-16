package smartproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Resolver turns a host name into IP address strings.
type Resolver func(ctx context.Context, host string) ([]string, error)

// DialFunc opens a TCP connection; it lets DoH traffic itself travel over a
// working upstream path instead of the (possibly filtered) system route.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DoHEndpoint is a JSON DNS-over-HTTPS service (as served by Google and
// Cloudflare). Addr, when set, is the IP:port to connect to, so the lookup does
// not itself need DNS (the resolver's own name is often poisoned or filtered);
// ServerName is then the certificate name to verify.
type DoHEndpoint struct {
	URL        string // e.g. https://dns.google/resolve
	Accept     string // optional Accept header
	Addr       string // optional IP:port to dial instead of resolving the URL host
	ServerName string // certificate name when Addr is used (default: URL host)
}

// DefaultDoH lists two independent public resolvers, each reachable by several
// IP literals so that no step depends on the system resolver. Cloudflare's
// 104.16.248.249 / 104.16.249.249 sit inside the CDN ranges that are usually
// reachable even when 1.1.1.1 and 8.8.8.8 are not.
var DefaultDoH = []DoHEndpoint{
	{URL: "https://cloudflare-dns.com/dns-query", Accept: "application/dns-json", Addr: "104.16.248.249:443", ServerName: "cloudflare-dns.com"},
	{URL: "https://cloudflare-dns.com/dns-query", Accept: "application/dns-json", Addr: "104.16.249.249:443", ServerName: "cloudflare-dns.com"},
	{URL: "https://cloudflare-dns.com/dns-query", Accept: "application/dns-json", Addr: "1.1.1.1:443", ServerName: "cloudflare-dns.com"},
	{URL: "https://dns.google/resolve", Addr: "8.8.8.8:443", ServerName: "dns.google"},
	{URL: "https://dns.google/resolve", Addr: "8.8.4.4:443", ServerName: "dns.google"},
	{URL: "https://dns.google/resolve"},
}

type dohAnswer struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// lookupFunc resolves one host and says how long the answer may be cached.
type lookupFunc func(ctx context.Context, host string) ([]string, time.Duration, error)

// cachedResolver adds, around a lookup: IP-literal passthrough, a TTL cache,
// de-duplication of concurrent lookups for one host, and detachment from the
// caller's context. The last one matters: a race that is already won cancels
// its losers, and a cancelled lookup would never fill the cache.
func cachedResolver(lookup lookupFunc, budget time.Duration) Resolver {
	type result struct {
		ips []string
		err error
	}
	type entry struct {
		ips     []string
		expires time.Time
	}
	var mu sync.Mutex
	cache := map[string]entry{}
	inflight := map[string][]chan result{}

	run := func(host string) ([]string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		ips, ttl, err := lookup(ctx, host)
		if err != nil {
			return nil, err
		}
		if ttl < 30*time.Second {
			ttl = 30 * time.Second
		}
		mu.Lock()
		cache[host] = entry{ips: ips, expires: time.Now().Add(ttl)}
		mu.Unlock()
		return ips, nil
	}
	return func(ctx context.Context, host string) ([]string, error) {
		if net.ParseIP(host) != nil {
			return []string{host}, nil
		}
		mu.Lock()
		if e, ok := cache[host]; ok && time.Now().Before(e.expires) {
			mu.Unlock()
			return e.ips, nil
		}
		wait := make(chan result, 1)
		waiters, running := inflight[host]
		inflight[host] = append(waiters, wait)
		mu.Unlock()
		if !running {
			go func() {
				ips, err := run(host)
				mu.Lock()
				done := inflight[host]
				delete(inflight, host)
				mu.Unlock()
				for _, w := range done {
					w <- result{ips, err}
				}
			}()
		}
		select {
		case r := <-wait:
			return r.ips, r.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// NewDoH returns a caching resolver for A records. Certificates are always
// verified. Names that are already IP literals are returned as they are.
func NewDoH(endpoints []DoHEndpoint, dial DialFunc, roots *x509.CertPool) Resolver {
	return NewDoHType(endpoints, dial, roots, "A")
}

// NewDoHType is NewDoH for a record type: "A" (IPv4) or "AAAA" (IPv6). All
// endpoints are asked at once and the first usable answer wins, so a filtered
// provider or IP costs nothing while another one answers.
func NewDoHType(endpoints []DoHEndpoint, dial DialFunc, roots *x509.CertPool, qtype string) Resolver {
	clients := make([]*http.Client, len(endpoints))
	for i, ep := range endpoints {
		ep := ep
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: ep.ServerName}
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if ep.Addr != "" {
					addr = ep.Addr
				}
				return dial(ctx, network, addr)
			},
			TLSClientConfig:     cfg,
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: 6 * time.Second,
			DisableKeepAlives:   true,
		}
		clients[i] = &http.Client{Transport: transport, Timeout: 8 * time.Second}
	}
	want := 1
	if qtype == "AAAA" {
		want = 28
	}
	query := func(ctx context.Context, i int, host string) ([]string, time.Duration, error) {
		ep := endpoints[i]
		u, err := url.Parse(ep.URL)
		if err != nil {
			return nil, 0, err
		}
		q := u.Query()
		q.Set("name", host)
		q.Set("type", qtype)
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, 0, err
		}
		accept := ep.Accept
		if accept == "" {
			accept = "application/dns-json"
		}
		req.Header.Set("Accept", accept)
		resp, err := clients[i].Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, 0, fmt.Errorf("DoH %s: HTTP %d", u.Host, resp.StatusCode)
		}
		var ans dohAnswer
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&ans); err != nil {
			return nil, 0, err
		}
		var out []string
		ttl := 300
		for _, a := range ans.Answer {
			ip := net.ParseIP(a.Data)
			if a.Type == want && ip != nil && !Bogus(ip) {
				out = append(out, a.Data)
				if a.TTL > 0 && a.TTL < ttl {
					ttl = a.TTL
				}
			}
		}
		if len(out) == 0 {
			return nil, 0, fmt.Errorf("%s: no usable %s record from %s", host, qtype, u.Host)
		}
		return out, time.Duration(ttl) * time.Second, nil
	}
	lookup := func(ctx context.Context, host string) ([]string, time.Duration, error) {
		if len(endpoints) == 0 {
			return nil, 0, errors.New("no DoH endpoint configured")
		}
		rctx, cancel := context.WithCancel(ctx)
		defer cancel()
		type res struct {
			ips []string
			ttl time.Duration
			err error
		}
		ch := make(chan res, len(endpoints))
		for i := range endpoints {
			go func(i int) {
				ips, ttl, err := query(rctx, i, host)
				ch <- res{ips, ttl, err}
			}(i)
		}
		var last error
		for range endpoints {
			select {
			case r := <-ch:
				if r.err == nil {
					return r.ips, r.ttl, nil
				}
				last = r.err
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			}
		}
		return nil, 0, last
	}
	return cachedResolver(lookup, 12*time.Second)
}
