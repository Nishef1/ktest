package mobilebridge

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Nishef1/ktest/internal/wstunnel"
)

// TestWindscribeCarrier tests one explicit, authorized entry through the same
// Go WStunnel/Stealth probe as the CLI. No foreign proxy is silently launched.
// A certificate-valid SNI is required; this entry point never disables TLS
// verification or claims that a carrier handshake proves a working VPN.
func TestWindscribeCarrier(address, sni, host, transport string) (string, error) {
	name, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	port, portErr := strconv.Atoi(portText)
	if err != nil || net.ParseIP(name) == nil || portErr != nil || port < 1 || port > 65535 {
		return "", errors.New("enter a numeric Windscribe/CDN entry as IP:port")
	}
	address = net.JoinHostPort(name, strconv.Itoa(port))
	sni, host = strings.TrimSpace(sni), strings.TrimSpace(host)
	if !validCarrierName(sni) || !validCarrierName(host) {
		return "", errors.New("a certificate-valid TLS name and HTTP hostname are required")
	}
	if transport != "wstunnel" && transport != "stealth" {
		return "", errors.New("choose wstunnel or stealth")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	result := wstunnel.Probe(ctx, transport, wstunnel.Config{
		Addr: address, SNI: sni, Host: host, Verify: true, Timeout: 10 * time.Second,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
		},
	})
	raw, err := json.Marshal(result)
	return string(raw), err
}

func validCarrierName(name string) bool {
	if len(name) == 0 || len(name) > 253 || net.ParseIP(name) != nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
