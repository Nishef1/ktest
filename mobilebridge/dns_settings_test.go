package mobilebridge

import (
	"testing"
)

func TestSetDNSOverrideValidatesAndCanReset(t *testing.T) {
	if err := SetDNSOverride("1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if got := currentDNSOverride(); got != "1.1.1.1:53" {
		t.Fatalf("unexpected normalized override %q", got)
	}
	if err := SetDNSOverride("dns.google"); err == nil {
		t.Fatal("accepted a hostname that could recurse through system DNS")
	}
	if got := currentDNSOverride(); got != "1.1.1.1:53" {
		t.Fatalf("invalid update changed active override: %q", got)
	}
	if err := SetDNSOverride(""); err != nil {
		t.Fatal(err)
	}
	if got := currentDNSOverride(); got != "" {
		t.Fatalf("empty override did not restore automatic DNS: %q", got)
	}
}

func TestScanDNSRejectsInvalidListBeforeNetworkIO(t *testing.T) {
	if _, err := ScanDNS("dns.google"); err == nil {
		t.Fatal("accepted a hostname in a DNS IP scan")
	}
	if _, err := ScanDNS(""); err == nil {
		t.Fatal("accepted an empty DNS scan")
	}
}
