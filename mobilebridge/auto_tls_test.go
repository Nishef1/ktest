package mobilebridge

import (
	"testing"
	"time"
)

func TestAutoTLSCalibrationCooldownPerNetwork(t *testing.T) {
	now := time.Now()
	net := "fixture-auto-tls-network"
	opt := "auto,auto,auto"
	if !allowAutoTLSProbe(net, opt, now) {
		t.Fatal("first calibration was skipped")
	}
	if allowAutoTLSProbe(net, opt, now.Add(time.Second)) {
		t.Fatal("blocked gateway would delay every new connection")
	}
	if !allowAutoTLSProbe(net+"-new", opt, now.Add(time.Second)) {
		t.Fatal("network handover failed to trigger recalibration")
	}
	if !allowAutoTLSProbe(net, "new-options", now.Add(time.Second)) {
		t.Fatal("user change should invalidate prior calibration attempt")
	}
	if allowAutoTLSProbe("", opt, now) {
		t.Fatal("no network should not trigger a direct calibration")
	}
}
