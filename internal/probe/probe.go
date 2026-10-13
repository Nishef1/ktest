package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config describes a single, bounded test. The optional overrides are intended
// for controlled DNS, CDN, and TLS routing experiments, not certificate bypass.
type Config struct {
	URL          string
	Host         string // HTTP Host header; defaults to the URL host.
	ServerName   string // TLS SNI and certificate verification name; defaults to URL hostname.
	ConnectAddr  string // Optional host:port to dial instead of the URL authority.
	Network      string // tcp, tcp4, or tcp6.
	Timeout      time.Duration
	MaxBodyBytes int64
	RootCAs      *x509.CertPool // Test-only/custom trust roots; system roots if nil.
}

type Result struct {
	TargetHost    string `json:"target_host"`
	TLSServerName string `json:"tls_server_name,omitempty"`
	HTTPHost      string `json:"http_host,omitempty"`
	ConnectAddr   string `json:"connect_addr,omitempty"`
	Network       string `json:"network"`
	Phase         string `json:"phase"`
	Reachable     bool   `json:"reachable"`
	Success       bool   `json:"success"`
	Status        int    `json:"http_status,omitempty"`
	Proto         string `json:"http_protocol,omitempty"`
	RemoteAddr    string `json:"remote_addr,omitempty"`
	BodyBytes     int64  `json:"body_bytes"`
	ElapsedMS     int64  `json:"elapsed_ms"`
	DNSMS         int64  `json:"dns_ms,omitempty"`
	ConnectMS     int64  `json:"connect_ms,omitempty"`
	TLSMS         int64  `json:"tls_ms,omitempty"`
	Error         string `json:"error,omitempty"`
}

type measurements struct {
	mu                               sync.Mutex
	phase                            string
	dnsStart, connectStart, tlsStart time.Time
	dnsMS, connectMS, tlsMS          int64
	remoteAddr                       string
}

func (m *measurements) record(phase string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.phase = phase
}

func (m *measurements) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.phase, m.dnsStart = "dns", time.Now()
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			m.mu.Lock()
			defer m.mu.Unlock()
			if !m.dnsStart.IsZero() {
				m.dnsMS = time.Since(m.dnsStart).Milliseconds()
			}
		},
		ConnectStart: func(_, _ string) {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.phase, m.connectStart = "tcp", time.Now()
		},
		ConnectDone: func(_, _ string, err error) {
			m.mu.Lock()
			defer m.mu.Unlock()
			if !m.connectStart.IsZero() {
				m.connectMS = time.Since(m.connectStart).Milliseconds()
			}
			if err == nil {
				m.phase = "tls_or_http"
			}
		},
		TLSHandshakeStart: func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.phase, m.tlsStart = "tls", time.Now()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			m.mu.Lock()
			defer m.mu.Unlock()
			if !m.tlsStart.IsZero() {
				m.tlsMS = time.Since(m.tlsStart).Milliseconds()
			}
			if err == nil {
				m.phase = "http"
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			m.mu.Lock()
			defer m.mu.Unlock()
			if info.Conn != nil {
				m.remoteAddr = info.Conn.RemoteAddr().String()
			}
		},
	}
}

// Run performs one GET, does not follow redirects, and caps response reading.
// It never disables TLS verification, uses a proxy, or stores response content.
func Run(parent context.Context, cfg Config) (Result, error) {
	if cfg.Network == "" {
		cfg.Network = "tcp"
	}
	if cfg.Network != "tcp" && cfg.Network != "tcp4" && cfg.Network != "tcp6" {
		return Result{}, errors.New("network must be tcp, tcp4, or tcp6")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 8 * time.Second
	}
	if cfg.Timeout < 0 || cfg.Timeout > 2*time.Minute {
		return Result{}, errors.New("timeout must be greater than zero and at most 2 minutes")
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 4096
	}
	if cfg.MaxBodyBytes < 0 || cfg.MaxBodyBytes > 64*1024 {
		return Result{}, errors.New("max body size must be between 1 and 65536 bytes")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
		return Result{}, errors.New("url must be an http(s) URL with a host and no user info")
	}
	if cfg.ConnectAddr != "" {
		if _, _, err := net.SplitHostPort(cfg.ConnectAddr); err != nil {
			return Result{}, fmt.Errorf("connect address must be host:port: %w", err)
		}
	}
	serverName := cfg.ServerName
	if serverName == "" {
		serverName = u.Hostname()
	}
	if strings.ContainsAny(serverName, "/:@ ") {
		return Result{}, errors.New("invalid TLS server name")
	}
	if cfg.Host != "" && (strings.ContainsAny(cfg.Host, "\r\n/ ") || len(cfg.Host) > 253) {
		return Result{}, errors.New("invalid HTTP Host")
	}

	res := Result{TargetHost: u.Hostname(), TLSServerName: serverName, HTTPHost: cfg.Host,
		ConnectAddr: cfg.ConnectAddr, Network: cfg.Network, Phase: "start"}
	m := &measurements{phase: "start"}
	ctx, cancel := context.WithTimeout(parent, cfg.Timeout)
	defer cancel()
	start := time.Now()

	dialer := &net.Dialer{Timeout: cfg.Timeout}
	transport := &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: true, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName, RootCAs: cfg.RootCAs},
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			if cfg.ConnectAddr != "" {
				addr = cfg.ConnectAddr
			}
			return dialer.DialContext(ctx, cfg.Network, addr)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, m.trace()), http.MethodGet, cfg.URL, nil)
	if err != nil {
		return Result{}, err
	}
	if cfg.Host != "" {
		req.Host = cfg.Host
	}
	req.Header.Set("Range", "bytes=0-4095")
	req.Header.Set("User-Agent", "ktest-probe/0.1")
	response, requestErr := client.Do(req)
	if requestErr == nil {
		res.Reachable = true
		res.Status, res.Proto = response.StatusCode, response.Proto
		res.Success = response.StatusCode >= 200 && response.StatusCode < 400
		res.Phase = "complete"
		bodyBytes, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, cfg.MaxBodyBytes))
		res.BodyBytes = bodyBytes
		_ = response.Body.Close()
		if readErr != nil {
			requestErr, res.Phase = readErr, "body"
		}
	}
	m.mu.Lock()
	res.DNSMS, res.ConnectMS, res.TLSMS, res.RemoteAddr = m.dnsMS, m.connectMS, m.tlsMS, m.remoteAddr
	if requestErr != nil {
		res.Phase = m.phase
		if res.Reachable {
			res.Phase = "body"
		}
		res.Error = requestErr.Error()
	}
	m.mu.Unlock()
	res.ElapsedMS = time.Since(start).Milliseconds()
	return res, nil
}
