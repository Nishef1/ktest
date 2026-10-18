package wstunnel

import (
	"context"
	"errors"
	"net"
	"time"
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
	CertificateVerified bool   `json:"certificate_verified"`
	WebSocket           bool   `json:"websocket"`
	ElapsedMS           int64  `json:"elapsed_ms"`
	Stage               string `json:"stage,omitempty"`
	Failure             string `json:"failure,omitempty"`
	VPNAuthenticated    bool   `json:"vpn_authenticated"`
}

// Probe opens only the outer WStunnel/Stealth carrier, then closes it. It
// sends no OpenVPN credentials or data. Both CLI and Android use this path.
func Probe(ctx context.Context, transport string, cfg Config) ProbeResult {
	r := ProbeResult{Entry: cfg.Addr, SNI: cfg.SNI, Transport: transport}
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
		r.CertificateVerified = cfg.Verify
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
	r.CertificateVerified = r.TLS && cfg.Verify
	return r
}
