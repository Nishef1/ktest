package wstunnel

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"sync/atomic"
	"time"
)

// Outer TLS trust levels reported by Probe. Only TrustPKI is HTTPS-grade
// server identity; TrustNameOnly means a VerifyPeer callback accepted the
// presented names while the chain did not verify against system roots, and
// the inner (e.g. OpenVPN) authentication remains the only server identity.
const (
	TrustPKI        = "pki"
	TrustNameOnly   = "name-only"
	TrustUnverified = "unverified"
)

// ProbeResult separates carrier readiness from OpenVPN authentication/data.
type ProbeResult struct {
	Entry     string `json:"entry"`
	SNI       string `json:"sni"`
	Transport string `json:"transport"`
	TCP       bool   `json:"tcp"`
	TLS       bool   `json:"tls_handshake"`
	// CertificateVerified means the outer TLS chain and SNI passed standard
	// verification. A custom VerifyPeer callback alone may only check a name
	// hint and must not be reported as chain verification.
	CertificateVerified bool `json:"certificate_verified"`
	// CertificateTrust is TrustPKI, TrustNameOnly or TrustUnverified once
	// TLS completed, and empty before that.
	CertificateTrust string `json:"certificate_trust,omitempty"`
	WebSocket        bool   `json:"websocket"`
	ElapsedMS        int64  `json:"elapsed_ms"`
	Stage            string `json:"stage,omitempty"`
	Failure          string `json:"failure,omitempty"`
	VPNAuthenticated bool   `json:"vpn_authenticated"`
}

// Probe opens only the outer WStunnel/Stealth carrier, then closes it. It
// sends no OpenVPN credentials or data. Both CLI and Android use this path.
func Probe(ctx context.Context, transport string, cfg Config) ProbeResult {
	r := ProbeResult{Entry: cfg.Addr, SNI: cfg.SNI, Transport: transport}
	// A name callback is kept as the acceptance rule; the chain is also
	// checked, for diagnostics only, so the two trust levels stay apart.
	var chained atomic.Bool
	if check := cfg.VerifyPeer; check != nil && !cfg.Verify {
		cfg.VerifyPeer = func(certs []*x509.Certificate) error {
			if err := check(certs); err != nil {
				return err
			}
			chained.Store(ChainVerified(certs))
			return nil
		}
	}
	trust := func() string {
		switch {
		case cfg.Verify || chained.Load():
			return TrustPKI
		case cfg.VerifyPeer != nil:
			return TrustNameOnly
		}
		return TrustUnverified
	}
	started := time.Now()
	var conn net.Conn
	var err error
	switch transport {
	case "stealth":
		conn, err = DialStealth(ctx, cfg)
	case "wstunnel":
		conn, err = Dial(ctx, cfg)
	default:
		r.Stage, r.Failure = "config", "transport must be wstunnel or stealth"
		return r
	}
	r.ElapsedMS = time.Since(started).Milliseconds()
	if err == nil {
		r.TCP, r.TLS, r.WebSocket = true, true, transport == "wstunnel"
		r.CertificateTrust = trust()
		r.CertificateVerified = r.CertificateTrust == TrustPKI
		_ = conn.Close()
		return r
	}
	r.Stage, r.Failure = "tcp", err.Error()
	var staged *StageError
	if errors.As(err, &staged) {
		r.Stage, r.Failure = staged.Stage, staged.Err.Error()
	}
	r.TCP = r.Stage == "tls" || r.Stage == "websocket"
	r.TLS = r.Stage == "websocket"
	if r.TLS {
		r.CertificateTrust = trust()
	}
	r.CertificateVerified = r.TLS && r.CertificateTrust == TrustPKI
	return r
}

// ChainVerified reports whether the presented leaf chains to a system root
// and is currently valid for one of its own DNS names. It does not bind the
// chain to the requested SNI, which a decoy or empty SNI cannot provide.
func ChainVerified(certs []*x509.Certificate) bool {
	if len(certs) == 0 || len(certs[0].DNSNames) == 0 {
		return false
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	for _, name := range certs[0].DNSNames {
		if _, err := certs[0].Verify(x509.VerifyOptions{DNSName: name, Intermediates: intermediates}); err == nil {
			return true
		}
	}
	return false
}
