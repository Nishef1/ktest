package mobilebridge

import "testing"

func TestConnectionIPCheckRequiresARunningProxy(t *testing.T) {
	StopProxy()
	if _, err := PublicIP(true); err == nil {
		t.Fatal("connection IP check must fail while disconnected")
	}
}
