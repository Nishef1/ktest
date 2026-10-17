package mobilebridge

import "testing"

func TestDiagnoseRejectsMalformedInputWithoutNetworking(t *testing.T) {
	for _, target := range []string{"", "file:///etc/passwd", "https://user:password@example.com", "https://example.com/#secret"} {
		if _, err := Diagnose(target); err == nil {
			t.Errorf("expected error for %q", target)
		}
	}
}
