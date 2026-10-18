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
	// FrontSNI, when set, is sent as the TLS server name instead of ServerName
	// (a decoy a filter does not block); the certificate is still verified for
	// ServerName and VerifyNames. The service routes by the HTTP Host, not by SNI.
	FrontSNI    string
	VerifyNames []string
	// DialTLS, when set, opens the finished TLS connection itself (for example
	// through Encrypted Client Hello); URL and Accept are still used for the request.
	DialTLS func(ctx context.Context) (net.Conn, error)
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
	// The reference MITM-DomainFronting project asks 1.1.1.1 under a decoy name.
	{URL: "https://cloudflare-dns.com/dns-query", Accept: "application/dns-json", Addr: "1.1.1.1:443", ServerName: "cloudflare-dns.com", FrontSNI: "www.microsoft.com", VerifyNames: []string{"one.one.one.one"}},
	{URL: "https://cloudflare-dns.com/dns-query", Accept: "application/dns-json", Addr: "1.0.0.1:443", ServerName: "cloudflare-dns.com", FrontSNI: "www.microsoft.com", VerifyNames: []string{"one.one.one.one"}},
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

// NewDoHType is NewDoH for a record type: "A" (IPv4) or "AAAA" (IPv6).
// The last successful endpoint starts first, with bounded hedges to the rest.
// Healthy HTTPS connections are reused across different destination names.
func NewDoHType(endpoints []DoHEndpoint, dial DialFunc, roots *x509.CertPool, qtype string) Resolver {
	clients := make([]*http.Client, len(endpoints))
	for i, ep := range endpoints {
		clients[i] = newDoHClient(ep, dial, roots)
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
		body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<16)+1))
		if err != nil {
			return nil, 0, err
		}
		if len(body) > 1<<16 {
			return nil, 0, errors.New("DoH response too large")
		}
		var ans dohAnswer
		if err := json.Unmarshal(body, &ans); err != nil {
			return nil, 0, err
		}
		// A DNS error response must never be accepted as a successful lookup,
		// even if its Answer section contains parseable addresses.
		if ans.Status != 0 {
			return nil, 0, fmt.Errorf("%s: DoH response status %d from %s", host, ans.Status, u.Host)
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
	var endpointMu sync.Mutex
	preferred := 0
	lookup := func(ctx context.Context, host string) ([]string, time.Duration, error) {
		if len(endpoints) == 0 {
			return nil, 0, errors.New("no DoH endpoint configured")
		}
		rctx, cancel := context.WithCancel(ctx)
		defer cancel()
		type res struct {
			index int
			ips   []string
			ttl   time.Duration
			err   error
		}
		ch := make(chan res, len(endpoints))
		endpointMu.Lock()
		first := preferred
		endpointMu.Unlock()
		order := []int{first}
		for i := range endpoints {
			if i != first {
				order = append(order, i)
			}
		}
		next, pending := 0, 0
		launch := func(n int) {
			for ; n != 0 && next < len(order); n-- {
				i := order[next]
				next++
				pending++
				go func() {
					ips, ttl, err := query(rctx, i, host)
					ch <- res{i, ips, ttl, err}
				}()
			}
		}
		launch(1)
		hedge := time.NewTimer(150 * time.Millisecond)
		defer hedge.Stop()
		expand := time.NewTimer(400 * time.Millisecond)
		defer expand.Stop()
		var last error
		for pending > 0 {
			select {
			case <-hedge.C:
				launch(2)
			case <-expand.C:
				launch(-1)
			case r := <-ch:
				pending--
				if r.err == nil {
					endpointMu.Lock()
					preferred = r.index
					endpointMu.Unlock()
					return r.ips, r.ttl, nil
				}
				last = r.err
				launch(1) // an immediate failure never waits for the next hedge
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			}
		}
		return nil, 0, last
	}
	return cachedResolver(lookup, 12*time.Second)
}

func newDoHClient(ep DoHEndpoint, dial DialFunc, roots *x509.CertPool) *http.Client {
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: ep.ServerName}
	if ep.FrontSNI != "" {
		cfg.ServerName = ep.FrontSNI
		cfg.InsecureSkipVerify = true // replaced by verification of the real names
		names := append([]string{ep.ServerName}, ep.VerifyNames...)
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			return verifyAnyName(raw, names, roots)
		}
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if ep.Addr != "" {
				addr = ep.Addr
			}
			return dial(ctx, network, addr)
		},
		TLSClientConfig: cfg, DialTLSContext: dialTLS(ep), ForceAttemptHTTP2: true,
		TLSHandshakeTimeout: 6 * time.Second, MaxIdleConns: 2,
		MaxIdleConnsPerHost: 2, MaxConnsPerHost: 4, IdleConnTimeout: 30 * time.Second,
	}
	return &http.Client{Transport: transport, Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("DoH redirects are not accepted") },
	}
}

// verifyAnyName accepts a certificate chain that is valid for at least one of
// names, checked against roots (nil: the system roots).
func verifyAnyName(raw [][]byte, names []string, roots *x509.CertPool) error {
	if len(raw) == 0 {
		return errors.New("no certificate")
	}
	certs := make([]*x509.Certificate, 0, len(raw))
	for _, r := range raw {
		c, err := x509.ParseCertificate(r)
		if err != nil {
			return err
		}
		certs = append(certs, c)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	var first error
	for _, n := range names {
		if _, err := certs[0].Verify(x509.VerifyOptions{DNSName: n, Roots: roots, Intermediates: inter}); err == nil {
			return nil
		} else if first == nil {
			first = err
		}
	}
	return first
}

// dialTLS adapts an endpoint's own TLS dialer to http.Transport; nil keeps the
// transport's ordinary dial and handshake.
func dialTLS(ep DoHEndpoint) func(context.Context, string, string) (net.Conn, error) {
	if ep.DialTLS == nil {
		return nil
	}
	return func(ctx context.Context, _, _ string) (net.Conn, error) { return ep.DialTLS(ctx) }
}
