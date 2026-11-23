package smartproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// ValidDestinationFamily accepts the legacy zero value as dual-stack.
func ValidDestinationFamily(family string) bool {
	return family == "" || family == "both" || family == "ipv4" || family == "ipv6"
}

func (p *Proxy) singleFamily() bool { return p.cfg.DestinationFamily != "both" && p.cfg.DestinationFamily != "" }

func (p *Proxy) familyAllows(host string) bool {
	ip := net.ParseIP(host)
	return !p.singleFamily() || ip == nil || (ip.To4() != nil) == (p.cfg.DestinationFamily == "ipv4")
}

func (p *Proxy) familyTarget(ctx context.Context, host string) (string, error) {
	if !p.singleFamily() {
		return host, nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if !p.familyAllows(host) {
			return "", errors.New("destination IP family is prohibited")
		}
		return ip.String(), nil
	}
	resolver := p.cfg.Resolve
	if p.cfg.DestinationFamily == "ipv6" {
		resolver = p.cfg.Resolve6
	}
	if resolver == nil {
		return "", errors.New("selected address-family resolver is unavailable")
	}
	rctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := resolver(rctx, host)
	if err != nil {
		return "", err
	}
	for _, candidate := range ips {
		if ip := net.ParseIP(candidate); ip != nil && p.familyAllows(candidate) && !Bogus(ip) {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no trusted %s address for destination", p.cfg.DestinationFamily)
}

// familyDNS returns a syntactically valid DNS NODATA response for the
// disallowed address type. Other types use the ordinary encrypted resolver.
// Application-level DoH may still discover other addresses; the actual
// destination socket policy remains the enforcement boundary.
func familyDNS(family string, exchange func(context.Context, []byte) ([]byte, error)) func(context.Context, []byte) ([]byte, error) {
	return func(ctx context.Context, query []byte) ([]byte, error) {
		end, err := dnsQuestionEnd(query)
		if err != nil || query[2]&0xf8 != 0 {
			return nil, errors.New("invalid DNS query")
		}
		qtype := binary.BigEndian.Uint16(query[end-4 : end-2])
		if family == "ipv4" && qtype == 28 || family == "ipv6" && qtype == 1 {
			response := append([]byte(nil), query[:end]...)
			response[2] = 0x80 | query[2]&1 // QR, preserve recursion desired
			response[3] = 0x80             // RA, NOERROR
			clear(response[6:12])         // zero answer/authority/additional counts
			return response, nil
		}
		if exchange == nil {
			return nil, errors.New("encrypted packet DNS unavailable")
		}
		return exchange(ctx, query)
	}
}

// DNS bootstrap is infrastructure, not application egress. In exit-only
// modes it still goes through a verified foreign route; a numeric resolver
// address must not be blocked just because its own family differs.
type dnsBootstrapKey struct{}

func (p *Proxy) DialVerifiedExitDNS(ctx context.Context, host, port string) (net.Conn, error) {
	if net.ParseIP(host) == nil {
		return nil, errors.New("DNS bootstrap requires a numeric resolver address")
	}
	return p.DialVerifiedExit(context.WithValue(ctx, dnsBootstrapKey{}, true), host, port)
}

// DialExitCarrierDNS preserves Aether's carrier-only policy (which may
// geolocate in Iran), without applying the application's family to DNS.
func (p *Proxy) DialExitCarrierDNS(ctx context.Context, host, port string) (net.Conn, error) {
	if net.ParseIP(host) == nil {
		return nil, errors.New("DNS bootstrap requires a numeric resolver address")
	}
	return p.DialExitCarrier(context.WithValue(ctx, dnsBootstrapKey{}, true), host, port)
}
