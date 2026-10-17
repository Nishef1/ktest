package mobilebridge

import "testing"

func TestVerifiedSocksRejectsUnapprovedModes(t *testing.T) {
    for _, mode := range []string{"", "windscribe", "unknown", "aether;direct"} {
        if _, err := VerifyExternalSocks("127.0.0.1:1234", mode); err == nil {
            t.Fatalf("accepted unapproved external mode %q", mode)
        }
    }
}

func TestVerifiedSocksRefusesRemoteEndpointWithoutDial(t *testing.T) {
    if _, err := VerifyExternalSocks("8.8.8.8:1080", "aether"); err == nil {
        t.Fatal("external non-local SOCKS endpoint must not pass strict verification")
    }
}
