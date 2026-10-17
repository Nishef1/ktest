package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/edges"
)

type observedExit struct {
	Address string
	IP      string
	Region  string
}

// verifyLocalUpstream checks the existing CLI -exit-socks route through a
// bounded, certificate-validated HTTPS request. It does not start a second
// Tor/Psiphon/Aether transport or authenticate the name of the external core.
// This is the same foreign exit verification implementation used by
// cmd/ktest, reached through internal/egresscheck rather than forked logic.
func verifyLocalUpstream(parent context.Context, address string) (observedExit, error) {
    host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
    if err != nil {
        return observedExit{}, errors.New("SOCKS address must be host:port")
    }
    port, err := strconv.Atoi(portText)
    if err != nil || port < 1 || port > 65535 {
        return observedExit{}, errors.New("invalid SOCKS port")
    }
    if host == "localhost" { host = "127.0.0.1" }
    ip := net.ParseIP(host)
    if ip == nil || !ip.IsLoopback() {
        return observedExit{}, errors.New("only a loopback SOCKS server is allowed")
    }
    address = net.JoinHostPort(host, portText)
    ipText, country, err := egresscheck.ProbeForeignExit(parent, address)
    if err != nil { return observedExit{}, err }
    return observedExit{Address: address, IP: ipText, Region: country}, nil
}

// TestFront calls the existing Go edges diagnostic. It does not create a
// second CDN-fronting transport or assert that a TLS handshake proves routing.
func TestFront(rawURL, sni, host, edgeIP string) (string, error) {
	edgeIP = strings.TrimSpace(edgeIP)
	if net.ParseIP(edgeIP) == nil {
		return "", errors.New("a single numeric edge IP is required")
	}
	plan := edges.Plan{
		URL: rawURL, SNI: sni, Host: host,
		IPs: []string{edgeIP}, Rounds: 1,
		Timeout: 7 * time.Second, Proof: false,
	}
	report, err := edges.Run(context.Background(), plan, nil)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
