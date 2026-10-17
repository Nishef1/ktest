package connectiondns

import (
	"context"
	"testing"
)

func TestMobileResolversRequireExitForStrictModes(t *testing.T) {
	for _, m := range []string{"aether", "psiphon", "tor"} {
		if _, _, err := MobileResolvers(m, ""); err == nil {
			t.Fatalf("%s allowed a system DNS path without verified SOCKS", m)
		}
		if _, _, err := MobilePacketDNS(m, ""); err == nil {
			t.Fatalf("%s allowed packet DNS without a verified exit", m)
		}
	}
}

func TestStrictPacketEndpointsCannotDialDirectECH(t *testing.T) {
	for _, endpoint := range PacketEndpoints(false) {
		if endpoint.DialTLS != nil || endpoint.Addr == "" || endpoint.FrontSNI != "" {
			t.Fatalf("strict wire DNS could escape the supplied exit dialer: %+v", endpoint)
		}
	}
}

func TestMobileResolversForBalancedAndFast(t *testing.T) {
	for _, m := range []string{"balanced", "fast"} {
		a, aaaa, err := MobileResolvers(m, "")
		if err != nil || a == nil || aaaa == nil {
			t.Fatalf("%s did not get trusted DNS resolvers: %v", m, err)
		}
		// IP literals are returned without touching a resolver or network.
		ips, err := a(context.Background(), "93.184.215.14")
		if err != nil || len(ips) != 1 || ips[0] != "93.184.215.14" {
			t.Fatalf("A literal passthrough failed: %v (%v)", ips, err)
		}
		ips6, err := aaaa(context.Background(), "2606:4700::1111")
		if err != nil || len(ips6) != 1 || ips6[0] != "2606:4700::1111" {
			t.Fatalf("AAAA literal passthrough failed: %v (%v)", ips6, err)
		}
	}
}
