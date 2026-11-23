package mobilebridge

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestConnectionIPCheckRequiresARunningProxy(t *testing.T) {
	StopProxy()
	for _, family := range []string{"ipv4", "ipv6", "both"} {
		if _, err := PublicIPForFamily(true, family); err == nil {
			t.Fatalf("%s connection IP check must fail while disconnected", family)
		}
	}
}

func TestIPFamilyValidationAndPinnedTargets(t *testing.T) {
	for _, f := range []string{"ipv4", "ipv6", "both"} {
		if !validIPFamily(f) {
			t.Fatalf("IP family %s rejected", f)
		}
	}
	for _, f := range []string{"", "any", "auto6", "tcp", "ipv7"} {
		if validIPFamily(f) {
			t.Fatalf("unexpected family %s accepted", f)
		}
		if _, err := PublicIPForFamily(false, f); err == nil {
			t.Fatal("invalid family passed before any network access")
		}
	}
	for _, family := range []struct {
		name string
		items []traceTarget
	}{
		{"ipv4", traceTargetsIPv4}, {"ipv6", traceTargetsIPv6},
	} {
		if len(family.items) < 2 {
			t.Fatal("each IP family needs independent numeric trace targets")
		}
		for _, target := range family.items {
			ipString, _, err := net.SplitHostPort(target.addr)
			if err != nil {
				t.Fatal(err)
			}
			ip := net.ParseIP(ipString)
			if ip == nil || (ip.To4() != nil) != (family.name == "ipv4") {
				t.Fatalf("%s target has wrong family: %s", family.name, target.addr)
			}
		}
	}
}

func TestDualFamilyReportPreservesPartialSuccessAndIPv4Priority(t *testing.T) {
	r := &publicIPReport{Via: "connection", Family: "both"}
	assignTraceResult(r, "ipv6", "2606:4700::1", "DE", nil)
	assignTraceResult(r, "ipv4", "", "", errors.New("IPv4 route blocked"))
	if r.IP != "2606:4700::1" || r.IPv4 != nil || r.IPv6 == nil ||
		!strings.Contains(r.IPv4Error, "blocked") {
		t.Fatalf("dual stack lost IPv6 success: %+v", r)
	}
	assignTraceResult(r, "ipv4", "1.2.3.4", "US", nil)
	if r.IP != "1.2.3.4" || r.IPv4.IP != "1.2.3.4" || r.IPv6.IP != "2606:4700::1" {
		t.Fatalf("dual stack overwrote a family: %+v", r)
	}
}
