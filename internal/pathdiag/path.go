package pathdiag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
)

// Config is an opt-in, low-volume diagnostic of independent transport stages.
// It neither modifies packets nor installs routes, DNS settings or certificates.
type Config struct {
	URL         string
	SNI         string
	ConnectAddr string
	Network     string
	Timeout     time.Duration
	RootCAs     *x509.CertPool // for controlled local tests; defaults to system roots
}

// Result deliberately distinguishes name resolution, TCP establishment and
// TLS certificate-verified handshakes. It does not measure HTTP or VPN egress.
type Result struct {
	TargetHost      string `json:"target_host"`
	Network         string `json:"network"`
	ConnectOverride bool   `json:"connect_override"`
	DNSStatus       string `json:"dns_status"`
	DNSIPv4Count    int    `json:"dns_ipv4_count"`
	DNSIPv6Count    int    `json:"dns_ipv6_count"`
	DNSDurationMS   int64  `json:"dns_duration_ms"`
	DNSError        string `json:"dns_error,omitempty"`
	TCPStatus       string `json:"tcp_status"`
	TCPDurationMS   int64  `json:"tcp_duration_ms"`
	TCPError        string `json:"tcp_error,omitempty"`
	TLSStatus       string `json:"tls_status"`
	TLSDurationMS   int64  `json:"tls_duration_ms"`
	TLSVersion      string `json:"tls_version,omitempty"`
	ALPN            string `json:"alpn,omitempty"`
	TLSError        string `json:"tls_error,omitempty"`
	Outcome         string `json:"outcome"`
	TotalDurationMS int64  `json:"total_duration_ms"`
}

func Run(parent context.Context, cfg Config) (res Result, runErr error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return Result{}, errors.New("URL must use http or https, with a hostname and without user info")
	}
	if cfg.Network == "" {
		cfg.Network = "tcp"
	}
	if cfg.Network != "tcp" && cfg.Network != "tcp4" && cfg.Network != "tcp6" {
		return Result{}, errors.New("network must be tcp, tcp4, or tcp6")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 8 * time.Second
	}
	if cfg.Timeout < 0 || cfg.Timeout > 30*time.Second {
		return Result{}, errors.New("timeout must be 1ns..30s")
	}
	if strings.ContainsAny(cfg.SNI, "/:@ \t\r\n") {
		return Result{}, errors.New("invalid SNI")
	}
	if cfg.SNI != "" && u.Scheme != "https" {
		return Result{}, errors.New("SNI only applies to HTTPS")
	}
	if cfg.ConnectAddr != "" {
		_, p, err := net.SplitHostPort(cfg.ConnectAddr)
		if err != nil || p == "" {
			return Result{}, errors.New("-connect must be a host:port address")
		}
	}
	ctx, cancel := context.WithTimeout(parent, cfg.Timeout)
	defer cancel()
	start := time.Now()
	res = Result{TargetHost: u.Hostname(), Network: cfg.Network, ConnectOverride: cfg.ConnectAddr != "", DNSStatus: "not_run", TCPStatus: "not_run", TLSStatus: "not_run"}

	// DNS is measured independently even with a pinned TCP address: a DNS
	// failure is not allowed to mask a functional, explicitly pinned route.
	// With a pinned address the lookup runs concurrently, so a resolver that
	// hangs (common on filtered networks) cannot consume the TCP/TLS budget.
	dnsDone := make(chan dnsOutcome, 1)
	go func() { dnsDone <- lookupHost(ctx, u.Hostname()) }()
	collectDNS := func() error {
		out := <-dnsDone
		res.DNSDurationMS = out.duration.Milliseconds()
		if out.err != nil {
			res.DNSStatus, res.DNSError = "failed", out.err.Error()
			return out.err
		}
		res.DNSStatus = "ok"
		res.DNSIPv4Count, res.DNSIPv6Count = out.v4, out.v6
		return nil
	}
	if cfg.ConnectAddr == "" {
		// Without a pinned address the dial depends on this lookup.
		if collectDNS() != nil {
			res.TCPStatus, res.TLSStatus, res.Outcome = "skipped", "skipped", "dns_unresolved"
			res.TotalDurationMS = time.Since(start).Milliseconds()
			return res, nil
		}
	} else {
		defer func() {
			_ = collectDNS()
			res.TotalDurationMS = time.Since(start).Milliseconds()
		}()
	}

	address := u.Host
	if u.Port() == "" {
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		address = net.JoinHostPort(u.Hostname(), port)
	}
	if cfg.ConnectAddr != "" {
		address = cfg.ConnectAddr
	}
	tcpStart := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, cfg.Network, address)
	res.TCPDurationMS = time.Since(tcpStart).Milliseconds()
	if err != nil {
		res.TCPStatus, res.TCPError, res.TLSStatus, res.Outcome = "failed", err.Error(), "skipped", "tcp_unavailable"
		res.TotalDurationMS = time.Since(start).Milliseconds()
		return res, nil
	}
	res.TCPStatus = "ok"
	defer conn.Close()
	if u.Scheme == "http" {
		res.TLSStatus, res.Outcome = "not_applicable", "tcp_connected_no_http_test"
		res.TotalDurationMS = time.Since(start).Milliseconds()
		return res, nil
	}

	sni := cfg.SNI
	if sni == "" {
		sni = u.Hostname()
	}
	// InsecureSkipVerify must remain false, including in controlled experiments.
	tlsConn := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs, ServerName: sni})
	tlsStart := time.Now()
	err = tlsConn.HandshakeContext(ctx)
	res.TLSDurationMS = time.Since(tlsStart).Milliseconds()
	if err != nil {
		res.TLSStatus, res.TLSError, res.Outcome = "failed", err.Error(), "tls_unavailable"
	} else {
		state := tlsConn.ConnectionState()
		res.TLSStatus, res.Outcome = "verified", "tls_verified_no_http_test"
		res.TLSVersion, res.ALPN = tls.VersionName(state.Version), state.NegotiatedProtocol
	}
	_ = tlsConn.Close()
	res.TotalDurationMS = time.Since(start).Milliseconds()
	return res, nil
}

type dnsOutcome struct {
	v4, v6   int
	duration time.Duration
	err      error
}

func lookupHost(ctx context.Context, host string) dnsOutcome {
	began := time.Now()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	out := dnsOutcome{duration: time.Since(began), err: err}
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			out.v4++
		} else if ip.IP.To16() != nil {
			out.v6++
		}
	}
	return out
}
