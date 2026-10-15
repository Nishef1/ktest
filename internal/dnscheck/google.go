package dnscheck

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Result describes a real DNS query, not ICMP ping or an open TCP port.
type Result struct {
	UDP   bool
	TCP   bool
	Notes []string
}

// CheckGoogleDNS queries the authoritative Google DNS identity TXT over both
// UDP and TCP to 8.8.8.8:53. The answer must contain Google's documented marker.
// It only measures this moment's reachability; UDP 53 is not encrypted.
func CheckGoogleDNS(ctx context.Context) Result {
	r := Result{}
	r.UDP = check(ctx, "udp", "8.8.8.8:53")
	r.TCP = check(ctx, "tcp", "8.8.8.8:53")
	if r.UDP {
		r.Notes = append(r.Notes, "8.8.8.8 UDP DNS identity verified")
	}
	if r.TCP {
		r.Notes = append(r.Notes, "8.8.8.8 TCP DNS identity verified")
	}
	if !r.UDP && !r.TCP {
		r.Notes = append(r.Notes, "8.8.8.8 DNS did not answer the identity test; local DNS or encrypted alternatives may still work")
	}
	return r
}

func check(parent context.Context, network, remote string) bool {
	ctx, cancel := context.WithTimeout(parent, 2500*time.Millisecond)
	defer cancel()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, remote)
	}}
	txt, err := resolver.LookupTXT(ctx, "test.dns.google.com.")
	if err != nil {
		return false
	}
	for _, item := range txt {
		if strings.Contains(item, "Thanks for using Google Public DNS.") {
			return true
		}
	}
	return false
}

// Format is deliberately short for an interactive, non-blocking terminal.
func (r Result) Format() string {
	return fmt.Sprintf("Google DNS 8.8.8.8: UDP=%t TCP=%t (actual TXT query)", r.UDP, r.TCP)
}
