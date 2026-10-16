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

// DoHEndpoint is a JSON DNS-over-HTTPS service (RFC 8484 JSON, as served by
// Google and Cloudflare).
type DoHEndpoint struct {
	URL    string // e.g. https://dns.google/resolve
	Accept string // optional Accept header
}

// DefaultDoH are two independent public resolvers.
var DefaultDoH = []DoHEndpoint{
	{URL: "https://dns.google/resolve"},
	{URL: "https://cloudflare-dns.com/dns-query", Accept: "application/dns-json"},
}

type dohAnswer struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// NewDoH returns a caching resolver. Certificates are always verified. Names
// that are already IP literals are returned as they are.
func NewDoH(endpoints []DoHEndpoint, dial DialFunc, roots *x509.CertPool) Resolver {
	return NewDoHType(endpoints, dial, roots, "A")
}

// NewDoHType is NewDoH for a record type: "A" (IPv4) or "AAAA" (IPv6).
func NewDoHType(endpoints []DoHEndpoint, dial DialFunc, roots *x509.CertPool, qtype string) Resolver {
	transport := &http.Transport{
		DialContext:         dial,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 6 * time.Second,
		DisableKeepAlives:   true,
	}
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	type entry struct {
		ips     []string
		expires time.Time
	}
	var mu sync.Mutex
	cache := map[string]entry{}

	query := func(ctx context.Context, ep DoHEndpoint, host, qtype string) ([]string, int, error) {
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
		resp, err := client.Do(req)
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
		want := 1
		if qtype == "AAAA" {
			want = 28
		}
		var out []string
		ttl := 300
		for _, a := range ans.Answer {
			if a.Type == want && net.ParseIP(a.Data) != nil {
				out = append(out, a.Data)
				if a.TTL > 0 && a.TTL < ttl {
					ttl = a.TTL
				}
			}
		}
		return out, ttl, nil
	}

	type result struct {
		ips []string
		err error
	}
	var inflight = map[string][]chan result{}

	resolve := func(host string) ([]string, error) {
		// Detached from any caller: a race that is already won must not cancel
		// the lookup, otherwise the answer is never cached for later attempts.
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		var lastErr error
		for _, ep := range endpoints {
			ips, ttl, err := query(ctx, ep, host, qtype)
			if err != nil {
				lastErr = err
				continue
			}
			if len(ips) == 0 {
				lastErr = fmt.Errorf("%s: no %s record", host, qtype)
				continue
			}
			if ttl < 30 {
				ttl = 30
			}
			mu.Lock()
			cache[host] = entry{ips: ips, expires: time.Now().Add(time.Duration(ttl) * time.Second)}
			mu.Unlock()
			return ips, nil
		}
		if lastErr == nil {
			lastErr = errors.New("no DoH endpoint configured")
		}
		return nil, lastErr
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
				ips, err := resolve(host)
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
