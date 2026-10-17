package mobilebridge

import (
    "context"
    "strings"
    "testing"
)

func TestUpstreamStrictValidation(t *testing.T) {
    inputs := []string{"203.0.113.1:1080", "example.com:1080", "127.0.0.1:0", "127.0.0.1:65536", "invalid"}
    for _, x := range inputs {
        if _, err := verifyLocalUpstream(context.Background(), x); err == nil {
            t.Errorf("bad upstream accepted: %s", x)
        }
    }
    if _, err := StartProxyWithUpstream("tor", ""); err == nil ||
        !strings.Contains(err.Error(), "not available") {
        t.Fatal("An unported Tor mode must not start a second transport")
    }
    if _, err := TestFront("https://example.com", "example.com", "example.com", "bad-ip"); err == nil {
        t.Fatal("accepted invalid edge IP")
    }
}
