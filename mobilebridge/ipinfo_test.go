package mobilebridge

import (
	"errors"
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

func TestIPFamilyValidation(t *testing.T) {
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
