package access

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Proxy is a deliberately restricted HTTP CONNECT proxy. It never forwards
// unknown domains directly, never decrypts TLS, and never proxies HTTP URLs.
// Every allowed name is explicitly mapped to a locally running SNI bridge.
type Proxy struct {
	routes map[string]string
	dialer net.Dialer
}

func NewProxy(domains []string, bridge string) (*Proxy, error) {
	h, _, err := net.SplitHostPort(bridge)
	if err != nil {
		return nil, fmt.Errorf("invalid bridge address: %w", err)
	}
	ip := net.ParseIP(h)
	if !(strings.EqualFold(h, "localhost") || (ip != nil && ip.IsLoopback())) {
		return nil, errors.New("bridge must listen on loopback")
	}
	if len(domains) == 0 {
		return nil, errors.New("at least one -domain is required")
	}
	m := make(map[string]string, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
		if !validName(d) {
			return nil, fmt.Errorf("invalid domain: %q", d)
		}
		if _, ok := m[d]; ok {
			return nil, fmt.Errorf("duplicate domain: %q", d)
		}
		m[d] = bridge
	}
	return &Proxy{routes: m, dialer: net.Dialer{Timeout: 5 * time.Second, KeepAlive: 25 * time.Second}}, nil
}

func validName(s string) bool {
	if len(s) < 1 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
		return
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil || port != "443" {
		http.Error(w, "HTTPS CONNECT on port 443 only", http.StatusForbidden)
		return
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	bridge, ok := p.routes[host]
	if !ok {
		http.Error(w, "domain not configured", http.StatusForbidden)
		return
	}
	upstream, err := p.dialer.DialContext(r.Context(), "tcp", bridge)
	if err != nil {
		http.Error(w, "local bridge unavailable", http.StatusBadGateway)
		return
	}
	h, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "connection upgrade unsupported", http.StatusInternalServerError)
		return
	}
	client, buffered, err := h.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	defer client.Close()
	defer upstream.Close()
	if _, err = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	// Hijack may have buffered TLS ClientHello bytes already read by net/http.
	// Preserve them instead of dropping early client traffic.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, bufferedSource(buffered, client))
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	_, _ = io.Copy(client, upstream)
	if tc, ok := client.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	_ = client.SetReadDeadline(time.Now())
	wg.Wait()
}

func bufferedSource(buffered *bufio.ReadWriter, client net.Conn) io.Reader {
	// buffered.Reader delegates to client after its buffered data is drained.
	return buffered.Reader
}

func Listen(ctx context.Context, addr string, handler http.Handler) error {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(h)
	if !(strings.EqualFold(h, "localhost") || (ip != nil && ip.IsLoopback())) {
		return errors.New("proxy must bind to loopback")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 6 * time.Second}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = srv.Shutdown(shutdownCtx)
			cancel()
		case <-done:
		}
	}()
	err = srv.Serve(ln)
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
