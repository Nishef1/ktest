package mobilebridge

import (
	"testing"
	"time"
)

func TestAutomaticCDNScannerGates(t *testing.T) {
	dir := t.TempDir()
	if autoEdgeEligible("fast", dir) {
		t.Fatal("automatic CDN scanning must not start without an identified network")
	}
	if autoEdgeEligible("tor", dir) {
		t.Fatal("Tor must not be delayed by provider scans")
	}
	now := time.Now()
	network := "isolated-test-network"
	if !reserveEdgeScan(network, "cloudflare", now) {
		t.Fatal("first scan reserved incorrectly")
	}
	if reserveEdgeScan(network, "cloudflare", now.Add(time.Second)) {
		t.Fatal("connection loop retried the same blocked CDN continuously")
	}
	if !reserveEdgeScan(network, "fastly", now.Add(time.Second)) {
		t.Fatal("a second provider must be independently eligible")
	}
	if !reserveEdgeScan(network+"-new", "cloudflare", now.Add(time.Second)) {
		t.Fatal("network handover must permit fresh CDN probing")
	}
}
